import React, { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { WarningRule, YaraRule, ClamAVInfo, ExternalConnectionPolicy, StatisticsData } from '../types';
import { apiClient } from '../api/client';
import { formatBytes, formatTimestamp, setTimeDisplayConfig } from '../utils/formatters';
import { Sparkles, Github, RefreshCw, CheckCircle2, AlertCircle } from 'lucide-react';
import { NewVersionModal } from './NewVersionModal';
import { APP_VERSION } from '../version';
import {
  FileFormatDefinition,
  DEFAULT_FILE_FORMATS,
  BUILTIN_FORMAT_PATTERNS,
  StructureType,
  STRUCTURE_COLORS,
  isBuiltinPattern,
} from '../utils/fileFormatPatterns';

interface SettingsViewProps {
  onBack: () => void;
}

import {
  KnownEvtxEvent,
  KNOWN_EVTX_EVENTS,
  CURATED_EVTX_EVENTS,
  DEFAULT_EVTX_BASELINE_IDS,
} from '../utils/knownEvtxEvents';

export const SettingsView: React.FC<SettingsViewProps> = ({ onBack }) => {
  const [token, setToken] = useState<string>(() => localStorage.getItem('fs_admin_token') || '');
  const [usernameInput, setUsernameInput] = useState<string>('');
  const [passwordInput, setPasswordInput] = useState<string>('');
  const [loginError, setLoginError] = useState<string>('');
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);
  const [customEvtxIdInput, setCustomEvtxIdInput] = useState<string>('');
  const [customEvtxSeverity, setCustomEvtxSeverity] = useState<'critical' | 'high' | 'medium' | 'low' | 'info'>('medium');
  const [evtxSearch, setEvtxSearch] = useState<string>('');
  const [evtxCategoryFilter, setEvtxCategoryFilter] = useState<string>('all');
  const [evtxGroupTab, setEvtxGroupTab] = useState<'both' | 'curated' | 'extended'>('both');

  // Active Tab
  const [activeTab, setActiveTab] = useState<'checks' | 'ui_preferences' | 'keys' | 'external' | 'clamav' | 'yara' | 'warninglist' | 'hex_patterns' | 'statistics' | 'history' | 'audit_logs' | 'api_docs' | 'archive_passwords' | 'cache' | 'cdr_policies' | 'evtx' | 'time'>('checks');

  // UI Preferences State (Telemetry & Diagnostics Tab Visibility - Hidden by default)
  const [showTelemetryDiagnostics, setShowTelemetryDiagnostics] = useState<boolean>(() => {
    try {
      return localStorage.getItem('fs_show_telemetry_diagnostics') === 'true';
    } catch {
      return false;
    }
  });

  // UI Preferences State (Check for GitHub updates - enabled by default)
  const [checkForUpdates, setCheckForUpdates] = useState<boolean>(() => {
    try {
      const v = localStorage.getItem('fs_check_for_updates');
      return v !== 'false';
    } catch {
      return true;
    }
  });
  const [isCheckingUpdates, setIsCheckingUpdates] = useState<boolean>(false);
  const [updateCheckStatus, setUpdateCheckStatus] = useState<{
    type: 'success' | 'has_update' | 'warning' | 'error';
    message: string;
    details?: any;
  } | null>(null);
  const [showUpdateModalFromSettings, setShowUpdateModalFromSettings] = useState<boolean>(false);
  const [updateModalInfo, setUpdateModalInfo] = useState<any>(null);

  // Time & Localization State
  const [timeSettings, setTimeSettings] = useState<any>({
    format: '24h',
    time_zone: 'UTC',
    show_timezone_suffix: true,
    show_milliseconds: false,
  });
  const [isSavingTimeSettings, setIsSavingTimeSettings] = useState<boolean>(false);

  // Settings State
  const [settingsData, setSettingsData] = useState<any>(null);
  const [externalPolicy, setExternalPolicy] = useState<ExternalConnectionPolicy | null>(null);
  const [clamavData, setClamavData] = useState<ClamAVInfo | null>(null);
  const [yaraRules, setYaraRules] = useState<YaraRule[]>([]);
  const [warningRules, setWarningRules] = useState<WarningRule[]>([]);
  const [statisticsData, setStatisticsData] = useState<StatisticsData | null>(null);

  // Format-Specific CDR & Sanitization Policies State
  const [cdrPolicies, setCdrPolicies] = useState<Record<string, any>>({});
  const [isLoadingCdrPolicies, setIsLoadingCdrPolicies] = useState<boolean>(false);
  const [cdrPolicyMsg, setCdrPolicyMsg] = useState<string>('');

  // Archive Auto-Unlocking Pipeline Dictionary State
  const [archivePasswords, setArchivePasswords] = useState<string[]>([]);
  const [newArchivePasswordInput, setNewArchivePasswordInput] = useState<string>('');
  const [isLoadingArchivePasswords, setIsLoadingArchivePasswords] = useState<boolean>(false);
  const [archivePasswordMsg, setArchivePasswordMsg] = useState<string>('');

  // Threat Intel Redis Cache State
  const [cacheStats, setCacheStats] = useState<any>(null);
  const [isLoadingCache, setIsLoadingCache] = useState<boolean>(false);
  const [cacheMsg, setCacheMsg] = useState<string>('');
  const [cacheMode, setCacheMode] = useState<'use_cache' | 'always_fetch'>('use_cache');
  const [cacheMaxAgeValue, setCacheMaxAgeValue] = useState<number>(24);
  const [cacheMaxAgeUnit, setCacheMaxAgeUnit] = useState<'hours' | 'days'>('hours');
  const [isSavingCachePolicy, setIsSavingCachePolicy] = useState<boolean>(false);

  // Upload History State
  const [uploadHistory, setUploadHistory] = useState<any[]>([]);
  const [historyEnabled, setHistoryEnabled] = useState<boolean>(true);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [historySearch, setHistorySearch] = useState<string>('');

  // Audit & Debug Logs State
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [auditCounts, setAuditCounts] = useState<{ TOTAL: number; DEBUG: number; INFO: number; WARNING: number; ERROR: number; CRITICAL: number }>({ TOTAL: 0, DEBUG: 0, INFO: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 });
  const [auditLogLevel, setAuditLogLevel] = useState<string>('INFO');
  const [auditFilterLevel, setAuditFilterLevel] = useState<string>('ALL');
  const [auditSearch, setAuditSearch] = useState<string>('');
  const [auditAutoRefresh, setAuditAutoRefresh] = useState<boolean>(false);
  const [isLoadingAuditLogs, setIsLoadingAuditLogs] = useState<boolean>(false);
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);

  // Active Tooltip for Upload History Hover popovers
  const [activeHistoryTooltip, setActiveHistoryTooltip] = useState<{
    type: 'vt' | 'clamav' | 'findings' | 'mitre' | 'previous_scans';
    entry: any;
    x: number;
    y: number;
    showAbove: boolean;
    isPinned?: boolean;
    previousScans?: any[];
  } | null>(null);
  const historyTooltipTimeoutRef = useRef<any>(null);

  const calculateTooltipCoords = (type: 'vt' | 'clamav' | 'findings' | 'mitre' | 'previous_scans', currentTarget: HTMLElement) => {
    const rect = currentTarget.getBoundingClientRect();
    const popoverWidth = (type === 'findings' || type === 'mitre' || type === 'previous_scans') ? 480 : 380;

    const spaceBelow = window.innerHeight - rect.bottom;
    const showAbove = spaceBelow < 360 && rect.top > 360;

    let left = rect.left + rect.width / 2 - popoverWidth / 2;
    if (left < 16) left = 16;
    if (left + popoverWidth > window.innerWidth - 16) {
      left = window.innerWidth - popoverWidth - 16;
    }

    const top = showAbove ? rect.top - 6 : rect.bottom + 6;
    return { x: left, y: top, showAbove };
  };

  const handleHistoryCellHover = (type: 'vt' | 'clamav' | 'findings' | 'mitre' | 'previous_scans', entry: any, e: React.MouseEvent) => {
    if (activeHistoryTooltip?.isPinned) {
      return;
    }
    if (historyTooltipTimeoutRef.current) {
      clearTimeout(historyTooltipTimeoutRef.current);
      historyTooltipTimeoutRef.current = null;
    }
    const coords = calculateTooltipCoords(type, e.currentTarget as HTMLElement);
    setActiveHistoryTooltip({
      type,
      entry,
      ...coords,
      isPinned: false,
    });
  };

  const handleHistoryCellClick = (type: 'vt' | 'clamav' | 'findings' | 'mitre' | 'previous_scans', entry: any, e: React.MouseEvent) => {
    e.stopPropagation();
    if (historyTooltipTimeoutRef.current) {
      clearTimeout(historyTooltipTimeoutRef.current);
      historyTooltipTimeoutRef.current = null;
    }
    // If clicking on the currently open and pinned tooltip for the same cell, dismiss it
    if (activeHistoryTooltip?.isPinned && activeHistoryTooltip.entry?.id === entry?.id && activeHistoryTooltip.type === type) {
      setActiveHistoryTooltip(null);
      return;
    }
    const coords = calculateTooltipCoords(type, e.currentTarget as HTMLElement);
    setActiveHistoryTooltip({
      type,
      entry,
      ...coords,
      isPinned: true,
    });
  };

  const handleHistoryCellLeave = () => {
    if (activeHistoryTooltip?.isPinned) return;
    if (historyTooltipTimeoutRef.current) {
      clearTimeout(historyTooltipTimeoutRef.current);
    }
    // Generous 500ms transit window so user can easily traverse gaps to popover/scrollbar
    historyTooltipTimeoutRef.current = setTimeout(() => {
      setActiveHistoryTooltip((prev) => (prev?.isPinned ? prev : null));
    }, 500);
  };

  const handleHistoryPopoverMouseEnter = () => {
    if (historyTooltipTimeoutRef.current) {
      clearTimeout(historyTooltipTimeoutRef.current);
      historyTooltipTimeoutRef.current = null;
    }
  };

  const handleHistoryPopoverMouseLeave = () => {
    if (activeHistoryTooltip?.isPinned) return;
    if (historyTooltipTimeoutRef.current) {
      clearTimeout(historyTooltipTimeoutRef.current);
    }
    historyTooltipTimeoutRef.current = setTimeout(() => {
      setActiveHistoryTooltip((prev) => (prev?.isPinned ? prev : null));
    }, 450);
  };

  // Dangerous URL file extensions
  const [dangerousExtensions, setDangerousExtensions] = useState<string[]>([]);
  const [newExtInput, setNewExtInput] = useState<string>('');
  const [isAddingExt, setIsAddingExt] = useState<boolean>(false);

  // Key verification states
  const [keyVerification, setKeyVerification] = useState<Record<string, { loading: boolean; valid?: boolean; message?: string }>>({});

  // Status & Feedback
  const [statusMsg, setStatusMsg] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isUpdatingClamav, setIsUpdatingClamav] = useState<boolean>(false);
  const [updateCheck, setUpdateCheck] = useState<{
    loading: boolean;
    checked: boolean;
    newer_available: boolean;
    message: string;
    remote_version?: number;
    remote_main_version?: number;
    remote_bytecode_version?: number;
    remote_date?: string;
    remote_signatures?: number;
    latest_definition_name?: string;
    latest_definition_summary?: string;
    local_version?: number;
    checked_at?: string;
    error?: string;
  }>({
    loading: false,
    checked: false,
    newer_available: false,
    message: '',
  });

  // ClamAV download progress tracking state & poll interval
  const [clamavDownloadProgress, setClamavDownloadProgress] = useState<{
    is_downloading: boolean;
    status: 'idle' | 'starting' | 'connecting' | 'downloading' | 'reloading' | 'completed' | 'error';
    current_file: string | null;
    current_file_index: number;
    total_files: number;
    downloaded_bytes: number;
    total_bytes: number;
    percent: number;
    speed_kbps: number;
    message: string;
    error: string | null;
    completed_at?: number | null;
  }>({
    is_downloading: false,
    status: 'idle',
    current_file: null,
    current_file_index: 0,
    total_files: 0,
    downloaded_bytes: 0,
    total_bytes: 0,
    percent: 0,
    speed_kbps: 0,
    message: '',
    error: null,
  });
  const clamavPollIntervalRef = useRef<any>(null);

  // Manual definition upload progress state
  const [uploadProgress, setUploadProgress] = useState<{
    active: boolean;
    percent: number;
    loaded: number;
    total: number;
  }>({
    active: false,
    percent: 0,
    loaded: 0,
    total: 0,
  });

  // YARA Rule Modal (Create & Edit)
  const [showYaraModal, setShowYaraModal] = useState<boolean>(false);
  const [editingYaraId, setEditingYaraId] = useState<string | null>(null);
  const [yaraName, setYaraName] = useState<string>('');
  const [yaraDesc, setYaraDesc] = useState<string>('');
  const [yaraSeverity, setYaraSeverity] = useState<string>('HIGH');
  const [yaraFormat, setYaraFormat] = useState<string>('ALL');
  const [yaraText, setYaraText] = useState<string>(`rule Custom_Suspicious_Pattern {
    meta:
        description = "Administrative custom indicator"
    strings:
        $s1 = "malicious_string_here" nocase
    condition:
        $s1
}`);
  const [yaraValidation, setYaraValidation] = useState<{ valid: boolean; error: string | null } | null>(null);
  const [isValidatingYara, setIsValidatingYara] = useState<boolean>(false);
  const [yaraError, setYaraError] = useState<string>('');

  // Warninglist Modal (Create & Edit)
  const [showWarningModal, setShowWarningModal] = useState<boolean>(false);
  const [editingWarningId, setEditingWarningId] = useState<string | null>(null);
  const [warnName, setWarnName] = useState<string>('');
  const [warnPattern, setWarnPattern] = useState<string>('');
  const [warnIsRegex, setWarnIsRegex] = useState<boolean>(false);
  const [warnSeverity, setWarnSeverity] = useState<'informational' | 'info' | 'low' | 'medium' | 'high' | 'critical'>('medium');
  const [warnDesc, setWarnDesc] = useState<string>('');
  const [warningError, setWarningError] = useState<string>('');

  // File Formats Management State
  const [fileFormats, setFileFormats] = useState<FileFormatDefinition[]>(DEFAULT_FILE_FORMATS);
  const [selectedFormatId, setSelectedFormatId] = useState<string>('pe');
  const [formatSearch, setFormatSearch] = useState<string>('');
  const [showFormatModal, setShowFormatModal] = useState<boolean>(false);
  const [editingFormatId, setEditingFormatId] = useState<string | null>(null);
  const [formatName, setFormatName] = useState<string>('');
  const [formatExtensions, setFormatExtensions] = useState<string[]>(['']);
  const [formatMagicSignatures, setFormatMagicSignatures] = useState<string[]>(['']);
  const [formatDesc, setFormatDesc] = useState<string>('');
  const [formatError, setFormatError] = useState<string>('');
  const [isSavingFormat, setIsSavingFormat] = useState<boolean>(false);

  // Forensic & Custom Hex Patterns
  const [customPatterns, setCustomPatterns] = useState<any[]>([]);
  const [showPatternModal, setShowPatternModal] = useState<boolean>(false);
  const [showPatternHelpModal, setShowPatternHelpModal] = useState<boolean>(false);
  const [editingPatternId, setEditingPatternId] = useState<string | null>(null);
  const [patternName, setPatternName] = useState<string>('');
  const [patternVal, setPatternVal] = useState<string>('');
  const [patternType, setPatternType] = useState<'hex' | 'string' | 'regex' | 'struct_field'>('string');
  const [patternColor, setPatternColor] = useState<string>('#10b981');
  const [patternDesc, setPatternDesc] = useState<string>('');
  const [patternCategory, setPatternCategory] = useState<string>('');
  const [patternOffset, setPatternOffset] = useState<string>('');
  const [patternLength, setPatternLength] = useState<string>('');
  const [patternStructureType, setPatternStructureType] = useState<StructureType>('header');
  const [patternFormat, setPatternFormat] = useState<string>('pe');
  const [patternError, setPatternError] = useState<string>('');
  const [isSavingPattern, setIsSavingPattern] = useState<boolean>(false);

  // Regex Help Modal
  const [showRegexHelpModal, setShowRegexHelpModal] = useState<boolean>(false);

  // ClamAV file upload
  const [uploadDefFile, setUploadDefFile] = useState<File | null>(null);
  const [isUploadingDef, setIsUploadingDef] = useState<boolean>(false);

  useEffect(() => {
    if (token) {
      fetchAll();
    }
  }, [token]);

  // Handle ESC key to close open modals & history popover, and dismiss pinned popovers on outside click
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (activeHistoryTooltip) setActiveHistoryTooltip(null);
        if (showRegexHelpModal) setShowRegexHelpModal(false);
        if (showWarningModal) setShowWarningModal(false);
        if (showYaraModal) setShowYaraModal(false);
        if (showPatternModal) setShowPatternModal(false);
        if (showPatternHelpModal) setShowPatternHelpModal(false);
        if (showFormatModal) setShowFormatModal(false);
      }
    };

    const handleClickOutside = (e: MouseEvent) => {
      if (activeHistoryTooltip?.isPinned) {
        const target = e.target as HTMLElement;
        if (!target.closest('#history-hover-popover')) {
          setActiveHistoryTooltip(null);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    document.addEventListener('click', handleClickOutside);

    if (showRegexHelpModal || showWarningModal || showYaraModal || showPatternModal) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('click', handleClickOutside);
      document.body.style.overflow = '';
    };
  }, [showRegexHelpModal, showWarningModal, showYaraModal, showPatternModal, activeHistoryTooltip]);

  const showNotification = (text: string, type: 'success' | 'error' = 'success') => {
    setStatusMsg({ text, type });
    setTimeout(() => setStatusMsg(null), 4500);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setLoginError('');

    try {
      const data = await apiClient.adminLogin(usernameInput, passwordInput);
      localStorage.setItem('fs_admin_token', data.token);
      setToken(data.token);
      window.dispatchEvent(new Event('auth_changed'));
    } catch (err: any) {
      setLoginError(err.message || 'Authentication failed.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = (msg?: string | React.MouseEvent) => {
    localStorage.removeItem('fs_admin_token');
    setToken('');
    setSettingsData(null);
    setExternalPolicy(null);
    setStatisticsData(null);
    setClamavData(null);
    setYaraRules([]);
    setWarningRules([]);
    setCustomPatterns([]);
    setUploadHistory([]);
    if (typeof msg === 'string') setLoginError(msg);
    window.dispatchEvent(new Event('auth_changed'));
  };

  const fetchAll = async () => {
    if (!token) return;
    setIsLoading(true);
    try {
      await Promise.allSettled([
        fetchSettings(),
        fetchExternalPolicy(),
        fetchClamav(),
        fetchYara(),
        fetchWarningRules(),
        fetchFileFormats(),
        fetchCustomPatterns(),
        fetchStatistics(),
        fetchDangerousExtensions(),
        fetchUploadHistory(),
        fetchArchivePasswords(),
        fetchCacheStats(),
      ]);
    } catch (e) {
      console.error('Failed to load settings data:', e);
    } finally {
      setIsLoading(false);
    }
  };

  // --- Archive Auto-Unlocking Pipeline Dictionary Handlers ---
  const fetchArchivePasswords = async () => {
    setIsLoadingArchivePasswords(true);
    try {
      const res = await apiClient.getArchivePasswords();
      setArchivePasswords(res.passwords || []);
    } catch (err: any) {
      console.error('Failed to fetch archive passwords:', err);
    } finally {
      setIsLoadingArchivePasswords(false);
    }
  };

  const handleAddArchivePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    const pw = newArchivePasswordInput.trim();
    if (!pw || !token) return;
    try {
      const res = await apiClient.addArchivePassword(token, pw);
      setArchivePasswords(res.passwords || []);
      setNewArchivePasswordInput('');
      setArchivePasswordMsg(`✓ Added "${pw}" to unlocking pipeline`);
      setTimeout(() => setArchivePasswordMsg(''), 3000);
    } catch (err: any) {
      setArchivePasswordMsg(`Error adding password: ${err.message}`);
    }
  };

  const handleDeleteArchivePassword = async (pw: string) => {
    if (!token) return;
    try {
      const res = await apiClient.deleteArchivePassword(token, pw);
      setArchivePasswords(res.passwords || []);
      setArchivePasswordMsg(`Removed "${pw}" from pipeline`);
      setTimeout(() => setArchivePasswordMsg(''), 3000);
    } catch (err: any) {
      setArchivePasswordMsg(`Error deleting password: ${err.message}`);
    }
  };

  const handleResetArchivePasswords = async () => {
    if (!token || !window.confirm('Reset archive unlocking passwords to default malware analysis dictionary?')) return;
    const defaults = ["infected", "malware", "password", "123456", "clean", "rules", "sample", "virus", "test"];
    try {
      const res = await apiClient.setArchivePasswords(token, defaults);
      setArchivePasswords(res.passwords || []);
      setArchivePasswordMsg('✓ Archive passwords restored to defaults');
      setTimeout(() => setArchivePasswordMsg(''), 3000);
    } catch (err: any) {
      setArchivePasswordMsg(`Error resetting passwords: ${err.message}`);
    }
  };

  // --- Threat Intel & External API Cache Handlers ---
  const fetchCacheStats = async () => {
    if (!token) return;
    setIsLoadingCache(true);
    try {
      const res = await apiClient.getCacheStats(token);
      setCacheStats(res.stats || null);
      if (res.stats?.policy) {
        setCacheMode(res.stats.policy.mode || 'use_cache');
        setCacheMaxAgeValue(Number(res.stats.policy.max_age_value) || 24);
        setCacheMaxAgeUnit(res.stats.policy.max_age_unit || 'hours');
      }
    } catch (err: any) {
      console.error('Failed to fetch cache stats:', err);
    } finally {
      setIsLoadingCache(false);
    }
  };

  const handleSaveCachePolicy = async () => {
    if (!token) return;
    setIsSavingCachePolicy(true);
    try {
      await apiClient.updateCacheSettings(token, {
        mode: cacheMode,
        max_age_value: cacheMaxAgeValue,
        max_age_unit: cacheMaxAgeUnit,
        auto_cache_enabled: true
      });
      setCacheMsg('✓ External API cache policy saved successfully.');
      fetchCacheStats();
      setTimeout(() => setCacheMsg(''), 3500);
    } catch (err: any) {
      setCacheMsg(`Error saving cache policy: ${err.message}`);
    } finally {
      setIsSavingCachePolicy(false);
    }
  };

  const handleClearCache = async (namespace?: string) => {
    if (!token) return;
    const promptMsg = namespace
      ? `Clear cached threat intelligence for namespace "${namespace}"?`
      : 'Flush ALL cached threat intelligence records (VirusTotal, CrowdStrike, ThreatFox, etc.) from Redis?';
    if (!window.confirm(promptMsg)) return;

    try {
      const res = await apiClient.clearCache(token, namespace);
      setCacheMsg(`✓ Flushed ${res.keys_deleted} cached items (${res.namespace})`);
      fetchCacheStats();
      setTimeout(() => setCacheMsg(''), 3500);
    } catch (err: any) {
      setCacheMsg(`Error clearing cache: ${err.message}`);
    }
  };

  // --- Format-Specific CDR & Sanitization Policy Handlers ---
  const fetchCdrPolicies = async () => {
    setIsLoadingCdrPolicies(true);
    try {
      const res = await apiClient.getCdrPolicies();
      setCdrPolicies(res.policies || {});
    } catch (err: any) {
      console.error('Failed to fetch CDR policies:', err);
    } finally {
      setIsLoadingCdrPolicies(false);
    }
  };

  const handleToggleCdrFormat = async (formatId: string, enabled: boolean) => {
    if (!token) return;
    const current = cdrPolicies[formatId] || {};
    const updatedFormat = { ...current, enabled };
    const updatedMap = { ...cdrPolicies, [formatId]: updatedFormat };
    setCdrPolicies(updatedMap);
    try {
      await apiClient.saveCdrPolicies(token, { format_id: formatId, policy: { enabled } });
      setCdrPolicyMsg(`✓ Updated CDR policy for ${current.format_name || formatId}`);
      setTimeout(() => setCdrPolicyMsg(''), 3000);
    } catch (err: any) {
      setCdrPolicyMsg(`Error: ${err.message}`);
    }
  };

  const handleToggleCdrOption = async (formatId: string, optionKey: string) => {
    if (!token) return;
    const current = cdrPolicies[formatId] || {};
    const opts: string[] = current.allowed_options || [];
    const newOpts = opts.includes(optionKey) ? opts.filter(o => o !== optionKey) : [...opts, optionKey];
    const updatedFormat = { ...current, allowed_options: newOpts };
    const updatedMap = { ...cdrPolicies, [formatId]: updatedFormat };
    setCdrPolicies(updatedMap);
    try {
      await apiClient.saveCdrPolicies(token, { format_id: formatId, policy: { allowed_options: newOpts } });
      setCdrPolicyMsg(`✓ Updated allowed options for ${current.format_name || formatId}`);
      setTimeout(() => setCdrPolicyMsg(''), 2500);
    } catch (err: any) {
      setCdrPolicyMsg(`Error: ${err.message}`);
    }
  };

  const handleToggleCdrOutputFormat = async (formatId: string, outFmt: string) => {
    if (!token) return;
    const current = cdrPolicies[formatId] || {};
    const fmts: string[] = current.allowed_output_formats || [];
    const newFmts = fmts.includes(outFmt) ? fmts.filter(f => f !== outFmt) : [...fmts, outFmt];
    if (newFmts.length === 0) return;
    const updatedFormat = { ...current, allowed_output_formats: newFmts };
    const updatedMap = { ...cdrPolicies, [formatId]: updatedFormat };
    setCdrPolicies(updatedMap);
    try {
      await apiClient.saveCdrPolicies(token, { format_id: formatId, policy: { allowed_output_formats: newFmts } });
      setCdrPolicyMsg(`✓ Updated output formats for ${current.format_name || formatId}`);
      setTimeout(() => setCdrPolicyMsg(''), 2500);
    } catch (err: any) {
      setCdrPolicyMsg(`Error: ${err.message}`);
    }
  };

  const fetchUploadHistory = async () => {
    if (!token) return;
    setHistoryLoading(true);
    try {
      const res = await apiClient.getUploadHistory(token);
      setUploadHistory(res.history || []);
      setHistoryEnabled(res.enabled);
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error(e);
    }
    finally { setHistoryLoading(false); }
  };

  const fetchAuditLogs = async (overrideFilter?: string, overrideSearch?: string) => {
    if (!token) return;
    setIsLoadingAuditLogs(true);
    try {
      const res = await apiClient.getAuditLogs(token, {
        level: overrideFilter !== undefined ? overrideFilter : auditFilterLevel,
        search: overrideSearch !== undefined ? overrideSearch : auditSearch,
        limit: 400,
      });
      setAuditLogs(res.logs || []);
      setAuditCounts(res.counts || { TOTAL: 0, DEBUG: 0, INFO: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 });
      if (res.current_level) setAuditLogLevel(res.current_level);
    } catch (err: any) {
      if (err.message?.includes('401') || err.message?.includes('auth') || err.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setIsLoadingAuditLogs(false);
    }
  };

  const handleClearAuditLogs = async () => {
    if (!token) return;
    if (!window.confirm('Are you sure you want to clear all active audit and debug logs?')) return;
    try {
      await apiClient.clearAuditLogs(token);
      setAuditLogs([]);
      setAuditCounts({ TOTAL: 0, DEBUG: 0, INFO: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 });
      showNotification('Audit logs cleared successfully', 'success');
    } catch (err: any) {
      showNotification(err.message || 'Failed to clear logs', 'error');
    }
  };

  const handleSetLogLevel = async (newLevel: string) => {
    if (!token) return;
    try {
      const res = await apiClient.setLogLevel(token, newLevel);
      setAuditLogLevel(res.level);
      showNotification(`System logging level set to ${res.level}`, 'success');
      fetchAuditLogs();
    } catch (err: any) {
      showNotification(err.message || 'Failed to set log level', 'error');
    }
  };

  useEffect(() => {
    if (activeTab !== 'audit_logs' || !auditAutoRefresh || !token) return;
    const interval = setInterval(() => {
      fetchAuditLogs();
    }, 3000);
    return () => clearInterval(interval);
  }, [activeTab, auditAutoRefresh, token, auditFilterLevel, auditSearch]);

  const fetchSettings = async () => {
    if (!token) return;
    try {
      const res = await apiClient.getSettings(token);
      setSettingsData(res.settings);
      if (res.settings?.ui_preferences?.show_telemetry_diagnostics !== undefined) {
        setShowTelemetryDiagnostics(Boolean(res.settings.ui_preferences.show_telemetry_diagnostics));
        localStorage.setItem('fs_show_telemetry_diagnostics', String(res.settings.ui_preferences.show_telemetry_diagnostics));
      }
      if (res.settings?.ui_preferences?.check_for_updates !== undefined) {
        setCheckForUpdates(Boolean(res.settings.ui_preferences.check_for_updates));
        localStorage.setItem('fs_check_for_updates', String(res.settings.ui_preferences.check_for_updates));
      }
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
    }
  };

  const fetchDangerousExtensions = async () => {
    try {
      const res = await apiClient.getDangerousExtensions(token);
      if (res && res.extensions) {
        setDangerousExtensions(res.extensions);
      }
    } catch (e) {
      console.error('Failed to load dangerous extensions:', e);
    }
  };

  const handleAddExtension = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newExtInput.trim().toLowerCase();
    if (!clean) return;
    setIsAddingExt(true);
    try {
      const res = await apiClient.addDangerousExtension(token, clean);
      setDangerousExtensions(res.extensions);
      setNewExtInput('');
      showNotification(`Extension '${clean.startsWith('.') ? clean : '.' + clean}' added to dangerous URL policy.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to add extension', 'error');
    } finally {
      setIsAddingExt(false);
    }
  };

  const handleDeleteExtension = async (ext: string) => {
    try {
      const res = await apiClient.deleteDangerousExtension(token, ext);
      setDangerousExtensions(res.extensions);
      showNotification(`Extension '${ext}' removed from dangerous URL policy.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to remove extension', 'error');
    }
  };

  const handleVerifyApiKey = async (service: string, inputElementId?: string) => {
    let customKey: string | undefined = undefined;
    if (inputElementId) {
      const el = document.getElementById(inputElementId) as HTMLInputElement;
      if (el && el.value && !el.value.includes('...') && !el.value.includes('*')) {
        customKey = el.value.trim();
      }
    }

    setKeyVerification((prev) => ({
      ...prev,
      [service]: { loading: true },
    }));

    try {
      const res = await apiClient.verifyApiKey(token, service, customKey);
      setKeyVerification((prev) => ({
        ...prev,
        [service]: { loading: false, valid: res.valid, message: res.message },
      }));
    } catch (err: any) {
      setKeyVerification((prev) => ({
        ...prev,
        [service]: { loading: false, valid: false, message: err.message || 'Verification connection failed' },
      }));
    }
  };

  const fetchExternalPolicy = async () => {
    if (!token) return;
    try {
      const res = await apiClient.getExternalPolicy(token);
      setExternalPolicy(res.policy);
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error('Failed to load external policy:', e);
    }
  };

  const fetchClamav = async () => {
    if (!token) return;
    try {
      const res = await apiClient.getClamavStatus(token);
      setClamavData(res.clamav);
      triggerBackgroundUpdateCheck(false);
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error('Failed to load ClamAV info:', e);
    }
  };

  const triggerBackgroundUpdateCheck = async (force = false) => {
    setUpdateCheck((prev) => ({ ...prev, loading: true, error: undefined }));
    try {
      const res = await apiClient.checkClamavUpdates(token, force);
      if (res && res.update_check) {
        const uc = res.update_check;
        setUpdateCheck({
          loading: false,
          checked: true,
          newer_available: !!uc.newer_available,
          message: uc.message || '',
          remote_version: uc.remote_version,
          remote_main_version: uc.remote_main_version,
          remote_bytecode_version: uc.remote_bytecode_version,
          remote_date: uc.remote_date,
          remote_signatures: uc.remote_signatures,
          latest_definition_name: uc.latest_definition_name,
          latest_definition_summary: uc.latest_definition_summary,
          local_version: uc.local_version,
          checked_at: uc.checked_at,
          error: uc.error,
        });
      } else {
        setUpdateCheck((prev) => ({ ...prev, loading: false, checked: true }));
      }
    } catch (err: any) {
      setUpdateCheck((prev) => ({
        ...prev,
        loading: false,
        checked: true,
        error: err.message,
        message: 'Could not query official mirror in the background.',
      }));
    }
  };

  const fetchYara = async () => {
    if (!token) return;
    try {
      const res = await apiClient.getYaraRules(token);
      setYaraRules(res.rules || []);
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error('Failed to load YARA rules:', e);
    }
  };

  const fetchWarningRules = async () => {
    if (!token) return;
    try {
      const res = await apiClient.getWarningRules(token);
      setWarningRules(res.rules || []);
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error('Failed to load warning rules:', e);
    }
  };

  const normalizeFormat = (f: any): FileFormatDefinition => {
    const exts: string[] = Array.isArray(f.extensions) && f.extensions.length > 0
      ? f.extensions
      : (f.defaultExtension || f.default_extension ? [f.defaultExtension || f.default_extension] : []);
    const magics: string[] = Array.isArray(f.magicSignatures) && f.magicSignatures.length > 0
      ? f.magicSignatures
      : (Array.isArray(f.magic_signatures) && f.magic_signatures.length > 0
        ? f.magic_signatures
        : (f.magicBytes || f.magic_bytes ? [f.magicBytes || f.magic_bytes] : []));
    return {
      id: f.id,
      name: f.name || f.id,
      defaultExtension: exts[0] || f.defaultExtension || f.default_extension || '',
      magicBytes: magics[0] || f.magicBytes || f.magic_bytes || '',
      extensions: exts,
      magicSignatures: magics,
      isSystem: f.isSystem ?? f.is_system ?? false,
      enabled: f.enabled ?? true,
      description: f.description || '',
    };
  };

  const fetchFileFormats = async () => {
    try {
      const res = await apiClient.getFileFormats();
      if (res.formats && res.formats.length > 0) {
        setFileFormats(res.formats.map(normalizeFormat));
      }
    } catch (e: any) {
      console.error('Failed to load file formats:', e);
    }
  };

  const fetchCustomPatterns = async () => {
    try {
      const [patRes, fmtRes] = await Promise.all([
        apiClient.getCustomPatterns(),
        apiClient.getFileFormats().catch(() => ({ formats: [] })),
      ]);
      setCustomPatterns(patRes.patterns || []);
      if (fmtRes.formats && fmtRes.formats.length > 0) {
        setFileFormats(fmtRes.formats.map(normalizeFormat));
      }
    } catch (e: any) {
      console.error('Failed to load custom patterns:', e);
    }
  };

  // File Format Handlers
  const openNewFormatModal = () => {
    setEditingFormatId(null);
    setFormatName('');
    setFormatExtensions(['']);
    setFormatMagicSignatures(['']);
    setFormatDesc('');
    setFormatError('');
    setShowFormatModal(true);
  };

  const openEditFormatModal = (fmt: any) => {
    setEditingFormatId(fmt.id);
    setFormatName(fmt.name || '');

    // Normalize extensions
    let exts: string[] = [];
    if (Array.isArray(fmt.extensions) && fmt.extensions.length > 0) {
      exts = [...fmt.extensions];
    } else if (fmt.defaultExtension || fmt.default_extension) {
      exts = [(fmt.defaultExtension || fmt.default_extension).trim()];
    }
    if (exts.length === 0) exts = [''];
    setFormatExtensions(exts);

    // Normalize magic signatures
    let magics: string[] = [];
    if (Array.isArray(fmt.magicSignatures) && fmt.magicSignatures.length > 0) {
      magics = [...fmt.magicSignatures];
    } else if (Array.isArray(fmt.magic_signatures) && fmt.magic_signatures.length > 0) {
      magics = [...fmt.magic_signatures];
    } else if (fmt.magicBytes || fmt.magic_bytes) {
      magics = [(fmt.magicBytes || fmt.magic_bytes).trim()];
    }
    if (magics.length === 0) magics = [''];
    setFormatMagicSignatures(magics);

    setFormatDesc(fmt.description || '');
    setFormatError('');
    setShowFormatModal(true);
  };

  const handleSaveFileFormat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    if (!formatName.trim()) {
      setFormatError('Format headline name is required.');
      return;
    }
    const cleanExts = formatExtensions.map(e => e.trim()).filter(Boolean);
    const cleanMagics = formatMagicSignatures.map(m => m.trim().toUpperCase()).filter(Boolean);
    if (cleanExts.length === 0) {
      setFormatError('At least one file extension is required (e.g. .exe)');
      return;
    }
    setIsSavingFormat(true);
    setFormatError('');
    try {
      if (editingFormatId) {
        const res = await apiClient.updateFileFormat(token, editingFormatId, {
          name: formatName.trim(),
          default_extension: cleanExts[0],
          extensions: cleanExts,
          magic_bytes: cleanMagics[0] || '',
          magic_signatures: cleanMagics,
          description: formatDesc.trim(),
        });
        const updated = normalizeFormat(res.format);
        setFileFormats(prev => prev.map(f => f.id === editingFormatId ? updated : f));
        showNotification('File format updated successfully', 'success');
      } else {
        const slug = cleanExts[0].replace(/^\./, '').toLowerCase() || formatName.toLowerCase().replace(/[^a-z0-9]/g, '_');
        const res = await apiClient.addFileFormat(token, {
          id: slug,
          name: formatName.trim(),
          default_extension: cleanExts[0],
          extensions: cleanExts,
          magic_bytes: cleanMagics[0] || '',
          magic_signatures: cleanMagics,
          description: formatDesc.trim(),
        });
        const added = normalizeFormat(res.format);
        setFileFormats(prev => [...prev, added]);
        setSelectedFormatId(added.id);
        showNotification('File format created successfully', 'success');
      }
      setShowFormatModal(false);
    } catch (err: any) {
      setFormatError(err.message || 'Failed to save file format');
    } finally {
      setIsSavingFormat(false);
    }
  };

  const handleResetPattern = async (patternId: string) => {
    if (!token) return;
    if (!window.confirm('Reset this built-in pattern to its default definition?')) return;
    try {
      await apiClient.resetCustomPattern(token, patternId);
      setCustomPatterns(prev => prev.filter(p => p.id !== patternId));
      showNotification('Pattern reset to factory default definition.', 'success');
    } catch (err: any) {
      showNotification(err.message || 'Failed to reset pattern', 'error');
    }
  };

  const handleToggleFormat = async (id: string) => {
    if (!token) return;
    try {
      const res = await apiClient.toggleFileFormat(token, id);
      setFileFormats(prev => prev.map(f => f.id === id ? { ...f, enabled: res.enabled } : f));
      showNotification(`File format ${res.enabled ? 'activated' : 'muted'}`, 'success');
    } catch (err: any) {
      showNotification(err.message || 'Failed to toggle file format', 'error');
    }
  };

  const handleDeleteFormat = async (id: string) => {
    if (!token) return;
    const fmt = fileFormats.find(f => f.id === id);
    if (fmt?.isSystem) {
      showNotification('System-created default file formats cannot be deleted, only disabled.', 'error');
      return;
    }
    if (!window.confirm(`Are you sure you want to delete file format "${fmt?.name || id}"?`)) return;
    try {
      await apiClient.deleteFileFormat(token, id);
      setFileFormats(prev => prev.filter(f => f.id !== id));
      if (selectedFormatId === id) {
        setSelectedFormatId('pe');
      }
      showNotification('File format deleted', 'success');
    } catch (err: any) {
      showNotification(err.message || 'Failed to delete file format', 'error');
    }
  };

  // Pattern Handlers
  const openNewPatternModal = (targetFormatId?: string) => {
    setEditingPatternId(null);
    setPatternName('');
    setPatternVal('');
    setPatternType('hex');
    setPatternColor('#10b981');
    setPatternDesc('');
    setPatternCategory('');
    setPatternOffset('');
    setPatternLength('');
    setPatternStructureType('header');
    setPatternFormat(targetFormatId || selectedFormatId || 'pe');
    setPatternError('');
    setShowPatternModal(true);
  };

  const openEditPatternModal = (pat: any) => {
    setEditingPatternId(pat.id);
    setPatternName(pat.name || '');
    setPatternVal(pat.pattern || '');
    setPatternType(pat.type || 'hex');
    setPatternColor(pat.color || '#10b981');
    setPatternDesc(pat.description || '');
    setPatternCategory(pat.category || '');
    setPatternOffset(pat.offset !== undefined && pat.offset !== null ? `0x${pat.offset.toString(16).toUpperCase()}` : '');
    setPatternLength(pat.length !== undefined && pat.length !== null ? String(pat.length) : '');
    setPatternStructureType(pat.structure_type || 'header');
    setPatternFormat(pat.appliesToFormat || selectedFormatId || 'pe');
    setPatternError('');
    setShowPatternModal(true);
  };

  const handleSaveCustomPattern = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    if (!patternName.trim()) {
      setPatternError('Pattern name is required.');
      return;
    }
    if (patternType !== 'struct_field' && !patternVal.trim()) {
      setPatternError('Pattern string or hex bytes are required.');
      return;
    }
    setIsSavingPattern(true);
    setPatternError('');
    try {
      let parsedOffset: number | undefined = undefined;
      if (patternOffset.trim()) {
        const trimmed = patternOffset.trim();
        parsedOffset = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? parseInt(trimmed, 16) : parseInt(trimmed, 10);
      }
      let parsedLength: number | undefined = undefined;
      if (patternLength.trim()) {
        parsedLength = parseInt(patternLength.trim(), 10);
      }

      if (editingPatternId) {
        const res = await apiClient.updateCustomPattern(token, editingPatternId, {
          name: patternName.trim(),
          pattern: patternVal.trim(),
          type: patternType,
          color: patternColor,
          description: patternDesc.trim(),
          category: patternCategory.trim() || undefined,
          offset: parsedOffset,
          length: parsedLength,
          structure_type: patternStructureType,
          appliesToFormat: patternFormat,
        });
        setCustomPatterns(prev => {
          const exists = prev.some(p => p.id === editingPatternId);
          if (exists) {
            return prev.map(p => p.id === editingPatternId ? { ...p, ...res.pattern, isBuiltin: true, isModified: true } : p);
          } else {
            return [...prev, { ...res.pattern, isBuiltin: true, isModified: true }];
          }
        });
        showNotification('Custom pattern updated successfully', 'success');
      } else {
        const res = await apiClient.addCustomPattern(token, {
          name: patternName.trim(),
          pattern: patternVal.trim(),
          type: patternType,
          color: patternColor,
          description: patternDesc.trim(),
          category: patternCategory.trim() || undefined,
          offset: parsedOffset,
          length: parsedLength,
          structure_type: patternStructureType,
          appliesToFormat: patternFormat,
        });
        setCustomPatterns(prev => [...prev, res.pattern]);
        showNotification('Custom pattern added successfully', 'success');
      }
      setShowPatternModal(false);
    } catch (err: any) {
      setPatternError(err.message || 'Failed to save custom pattern');
    } finally {
      setIsSavingPattern(false);
    }
  };

  const handleTogglePattern = async (id: string) => {
    if (!token) return;
    try {
      const res = await apiClient.toggleCustomPattern(token, id);
      setCustomPatterns(prev => {
        const exists = prev.some(p => p.id === id);
        if (exists) {
          return prev.map(p => p.id === id ? { ...p, enabled: res.enabled } : p);
        } else {
          return [...prev, { id, enabled: res.enabled, isBuiltin: true, isModified: true }];
        }
      });
      showNotification(`Pattern ${res.enabled ? 'activated' : 'muted'}`, 'success');
    } catch (err: any) {
      showNotification(err.message || 'Failed to toggle pattern', 'error');
    }
  };

  const handleDeletePattern = async (id: string) => {
    if (!token) return;
    if (!window.confirm('Are you sure you want to delete this pattern?')) return;
    try {
      await apiClient.deleteCustomPattern(token, id);
      setCustomPatterns(prev => prev.filter(p => p.id !== id));
      showNotification('Pattern deleted', 'success');
    } catch (err: any) {
      showNotification(err.message || 'Failed to delete pattern', 'error');
    }
  };

  const fetchStatistics = async () => {
    if (!token) return;
    try {
      const res = await apiClient.getStatistics(token);
      setStatisticsData(res.statistics);
    } catch (e: any) {
      if (e.message?.includes('401') || e.message?.includes('auth') || e.message?.includes('Unauthorized')) {
        handleLogout('Session expired. Please log in again.');
      }
      console.error('Failed to load statistics:', e);
    }
  };

  // Toggle Format / Global Check
  const handleToggleCheck = async (category: string, checkKey: string, currentValue: boolean) => {
    if (!settingsData) return;
    const isGlobal = category === 'global_checks';
    const updated = { ...settingsData };

    if (isGlobal) {
      updated.global_checks = {
        ...updated.global_checks,
        [checkKey]: !currentValue,
      };
    } else {
      updated.format_checks = {
        ...updated.format_checks,
        [category]: {
          ...updated.format_checks[category],
          [checkKey]: !currentValue,
        },
      };
    }

    try {
      const payload = isGlobal
        ? { global_checks: updated.global_checks }
        : { format_checks: updated.format_checks };
      const res = await apiClient.updateSettings(token, payload);
      setSettingsData(res.settings);
      showNotification('Inspection policy saved successfully.');
    } catch (err: any) {
      showNotification(err.message || 'Failed to update check', 'error');
    }
  };

  const handleBatchToggleFormat = async (category: string, enableAll: boolean) => {
    if (!settingsData?.format_checks?.[category]) return;
    const currentCategory = settingsData.format_checks[category];
    const updatedCategory: Record<string, boolean> = {};
    Object.keys(currentCategory).forEach(k => {
      updatedCategory[k] = enableAll;
    });
    const updatedFormatChecks = {
      ...settingsData.format_checks,
      [category]: updatedCategory,
    };
    try {
      const res = await apiClient.updateSettings(token, { format_checks: updatedFormatChecks });
      setSettingsData(res.settings);
      showNotification(`All ${category} inspection rules ${enableAll ? 'enabled' : 'disabled'}.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update check', 'error');
    }
  };

  // EVTX Timeline Event IDs & Severity Handlers (Curated Baseline imported from knownEvtxEvents)

  const fetchTimeSettings = async () => {
    try {
      const resp = await fetch('/api/settings/time-display');
      const data = await resp.json();
      const cfg = data.time_display || data;
      if (cfg && cfg.format) {
        setTimeSettings(cfg);
        setTimeDisplayConfig(cfg);
      }
    } catch {
      // fallback
    }
  };

  const handleSaveTimeSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingTimeSettings(true);
    try {
      const resp = await fetch('/api/settings/time-display', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(timeSettings),
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        setTimeDisplayConfig(data.time_display);
        setTimeSettings(data.time_display);
        showNotification('Time display and localization settings saved successfully.', 'success');
      } else {
        showNotification(data.detail || 'Failed to save time settings.', 'error');
      }
    } catch (err: any) {
      showNotification(err.message || 'Error saving time settings.', 'error');
    } finally {
      setIsSavingTimeSettings(false);
    }
  };

  const fetchUiPreferences = async () => {
    try {
      const res = await apiClient.getUiPreferences();
      if (res?.ui_preferences?.show_telemetry_diagnostics !== undefined) {
        setShowTelemetryDiagnostics(Boolean(res.ui_preferences.show_telemetry_diagnostics));
        localStorage.setItem('fs_show_telemetry_diagnostics', String(res.ui_preferences.show_telemetry_diagnostics));
      }
      if (res?.ui_preferences?.check_for_updates !== undefined) {
        setCheckForUpdates(Boolean(res.ui_preferences.check_for_updates));
        localStorage.setItem('fs_check_for_updates', String(res.ui_preferences.check_for_updates));
      }
    } catch {
      // fallback
    }
  };

  const handleToggleTelemetryDiagnostics = async (enable: boolean) => {
    setShowTelemetryDiagnostics(enable);
    try {
      localStorage.setItem('fs_show_telemetry_diagnostics', String(enable));
    } catch (e) {
      console.warn('Failed to save to localStorage', e);
    }
    window.dispatchEvent(new CustomEvent('fs-settings-changed', {
      detail: { show_telemetry_diagnostics: enable }
    }));

    if (token) {
      try {
        await apiClient.updateUiPreferences(token, { show_telemetry_diagnostics: enable });
        if (settingsData) {
          setSettingsData({
            ...settingsData,
            ui_preferences: {
              ...(settingsData.ui_preferences || {}),
              show_telemetry_diagnostics: enable,
            }
          });
        }
        showNotification(`Telemetry & Diagnostics tab ${enable ? 'is now visible' : 'is now hidden'} in file analysis dashboards.`);
      } catch (err: any) {
        console.warn('Backend UI preferences update error:', err);
      }
    } else {
      showNotification(`Telemetry & Diagnostics tab ${enable ? 'is now visible' : 'is now hidden'} in file analysis dashboards.`);
    }
  };

  const handleToggleCheckForUpdates = async (enable: boolean) => {
    setCheckForUpdates(enable);
    try {
      localStorage.setItem('fs_check_for_updates', String(enable));
    } catch (e) {
      console.warn('Failed to save to localStorage', e);
    }
    window.dispatchEvent(new CustomEvent('fs-settings-changed', {
      detail: { check_for_updates: enable }
    }));

    if (token) {
      try {
        await apiClient.updateUiPreferences(token, { check_for_updates: enable });
        if (settingsData) {
          setSettingsData({
            ...settingsData,
            ui_preferences: {
              ...(settingsData.ui_preferences || {}),
              check_for_updates: enable,
            }
          });
        }
        showNotification(`Automatic update check on startup ${enable ? 'is now enabled' : 'is now disabled'}.`);
      } catch (err: any) {
        console.warn('Backend UI preferences update error:', err);
      }
    } else {
      showNotification(`Automatic update check on startup ${enable ? 'is now enabled' : 'is now disabled'}.`);
    }
  };

  const handleManualCheckUpdates = async () => {
    setIsCheckingUpdates(true);
    setUpdateCheckStatus(null);
    try {
      const res = await apiClient.checkForUpdates(true);
      if (res.has_update) {
        setUpdateCheckStatus({
          type: 'has_update',
          message: `New version v${res.latest_version} is available!`,
          details: res,
        });
        setUpdateModalInfo(res);
        setShowUpdateModalFromSettings(true);
      } else if (res.external_blocked) {
        setUpdateCheckStatus({
          type: 'warning',
          message: 'External network connections are disabled in settings policy.',
        });
      } else if (res.success) {
        setUpdateCheckStatus({
          type: 'success',
          message: `You are running the latest version of FileSanitizer (v${res.current_version}).`,
        });
      } else {
        setUpdateCheckStatus({
          type: 'error',
          message: res.error || 'Failed to check GitHub for updates.',
        });
      }
    } catch (err: any) {
      setUpdateCheckStatus({
        type: 'error',
        message: err.message || 'Error communicating with update service.',
      });
    } finally {
      setIsCheckingUpdates(false);
    }
  };

  const handleToggleEvtxTimelineId = async (id: number) => {
    if (!settingsData) return;
    const currentIds: number[] = settingsData.evtx_timeline_event_ids || DEFAULT_EVTX_BASELINE_IDS;
    const newIds = currentIds.includes(id)
      ? currentIds.filter((x: number) => x !== id)
      : [...currentIds, id].sort((a: number, b: number) => a - b);

    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: newIds });
      setSettingsData(res.settings);
      showNotification(`Timeline Event ID ${id} ${currentIds.includes(id) ? 'removed from' : 'added to'} monitoring.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update EVTX timeline Event IDs', 'error');
    }
  };

  const handleChangeEvtxSeverity = async (eventId: number | string, newSeverity: string) => {
    const updated = {
      ...(settingsData?.evtx_severity_rules || {}),
      [String(eventId)]: newSeverity
    };
    try {
      const res = await apiClient.updateSettings(token, { evtx_severity_rules: updated });
      setSettingsData(res.settings);
      showNotification(`Event ID ${eventId} classification set to ${newSeverity.toUpperCase()}.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update Event ID severity', 'error');
    }
  };

  const handleAddCustomEvtxId = async (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseInt(customEvtxIdInput.trim(), 10);
    if (isNaN(parsed) || parsed <= 0) {
      showNotification('Please enter a valid positive integer Event ID', 'error');
      return;
    }
    const currentIds: number[] = settingsData?.evtx_timeline_event_ids || DEFAULT_EVTX_BASELINE_IDS;
    if (currentIds.includes(parsed)) {
      showNotification(`Event ID ${parsed} is already in the monitored list`, 'error');
      return;
    }
    const newIds = [...currentIds, parsed].sort((a: number, b: number) => a - b);
    const updatedSeverityRules = {
      ...(settingsData?.evtx_severity_rules || {}),
      [String(parsed)]: customEvtxSeverity
    };
    try {
      const res = await apiClient.updateSettings(token, {
        evtx_timeline_event_ids: newIds,
        evtx_severity_rules: updatedSeverityRules
      });
      setSettingsData(res.settings);
      setCustomEvtxIdInput('');
      showNotification(`Event ID ${parsed} added to EVTX monitoring with severity ${customEvtxSeverity.toUpperCase()}.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to add custom Event ID', 'error');
    }
  };

  const handleResetEvtxTimelineIds = async () => {
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: DEFAULT_EVTX_BASELINE_IDS });
      setSettingsData(res.settings);
      showNotification('EVTX timeline Event IDs restored to full incident response baseline.');
    } catch (err: any) {
      showNotification(err.message || 'Failed to reset EVTX timeline Event IDs', 'error');
    }
  };

  const handleSelectAllCuratedEvtxIds = async () => {
    const current = settingsData?.evtx_timeline_event_ids || DEFAULT_EVTX_BASELINE_IDS;
    const curatedIds = DEFAULT_EVTX_BASELINE_IDS;
    const newIds = Array.from(new Set([...current, ...curatedIds])).sort((a: number, b: number) => a - b);
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: newIds });
      setSettingsData(res.settings);
      showNotification(`All ${curatedIds.length} Curated Security & Forensic baseline Event IDs activated.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update EVTX timeline Event IDs', 'error');
    }
  };

  const handleDeselectCuratedEvtxIds = async () => {
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: [] });
      setSettingsData(res.settings);
      showNotification('All Event IDs removed from Curated and moved to Standard & Extended.');
    } catch (err: any) {
      showNotification(err.message || 'Failed to update EVTX timeline Event IDs', 'error');
    }
  };

  const handleSelectAllExtendedEvtxIds = async () => {
    const allKnown = KNOWN_EVTX_EVENTS.map((e) => e.id).sort((a: number, b: number) => a - b);
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: allKnown });
      setSettingsData(res.settings);
      showNotification(`All ${allKnown.length} Windows Event IDs activated and moved to Curated.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update EVTX timeline Event IDs', 'error');
    }
  };

  const handleSelectAllRecommendedEvtxIds = async () => {
    const allKnown = Array.from(new Set([...CURATED_EVTX_EVENTS.map((e) => e.id), ...DEFAULT_EVTX_BASELINE_IDS])).sort((a, b) => a - b);
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: allKnown });
      setSettingsData(res.settings);
      showNotification(`All ${allKnown.length} Curated Security Event IDs activated.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update EVTX timeline Event IDs', 'error');
    }
  };

  const handleSelectAllKnownEvtxIds = async () => {
    const allKnown = KNOWN_EVTX_EVENTS.map((e) => e.id).sort((a, b) => a - b);
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: allKnown });
      setSettingsData(res.settings);
      showNotification(`All ${allKnown.length} Windows Event IDs activated.`);
    } catch (err: any) {
      showNotification(err.message || 'Failed to update EVTX timeline Event IDs', 'error');
    }
  };

  const handleClearAllEvtxIds = async () => {
    try {
      const res = await apiClient.updateSettings(token, { evtx_timeline_event_ids: [] });
      setSettingsData(res.settings);
      showNotification('Cleared all monitored timeline Event IDs.');
    } catch (err: any) {
      showNotification(err.message || 'Failed to clear EVTX timeline Event IDs', 'error');
    }
  };

  // Update External Policy Toggle
  const handleToggleExternal = async (policyKey: keyof ExternalConnectionPolicy, currentValue: boolean) => {
    if (!externalPolicy) return;
    const updated = {
      ...externalPolicy,
      [policyKey]: !currentValue,
    };

    try {
      const res = await apiClient.updateExternalPolicy(token, updated);
      setExternalPolicy(res.policy);
      showNotification('External connection policy updated.');
    } catch (err: any) {
      showNotification(err.message || 'Failed to update policy', 'error');
    }
  };

  // Save API Keys
  const handleSaveApiKeys = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settingsData) return;
    const fd = new FormData(e.target as HTMLFormElement);
    const updates: Record<string, string> = {};

    const vt = fd.get('virustotal_api_key')?.toString();
    const sb = fd.get('safe_browsing_api_key')?.toString();
    const uh = fd.get('urlhaus_api_key')?.toString();
    const ab = fd.get('abuseipdb_api_key')?.toString();
    const otx = fd.get('alienvault_otx_api_key')?.toString();
    const ha = fd.get('hybrid_analysis_api_key')?.toString();
    const mx = fd.get('mxtoolbox_api_key')?.toString();
    const us = fd.get('urlscan_api_key')?.toString();
    const ipi = fd.get('ipinfo_api_key')?.toString();
    const sho = fd.get('shodan_api_key')?.toString();

    const isMaskedOrEmpty = (val: string | undefined) => {
      if (!val) return true;
      return val.includes('...') || val.includes('*');
    };

    if (vt !== undefined && !isMaskedOrEmpty(vt)) updates['virustotal_api_key'] = vt.trim();
    if (sb !== undefined && !isMaskedOrEmpty(sb)) updates['safe_browsing_api_key'] = sb.trim();
    if (uh !== undefined && !isMaskedOrEmpty(uh)) updates['urlhaus_api_key'] = uh.trim();
    if (ab !== undefined && !isMaskedOrEmpty(ab)) updates['abuseipdb_api_key'] = ab.trim();
    if (otx !== undefined && !isMaskedOrEmpty(otx)) updates['alienvault_otx_api_key'] = otx.trim();
    if (ha !== undefined && !isMaskedOrEmpty(ha)) updates['hybrid_analysis_api_key'] = ha.trim();
    if (mx !== undefined && !isMaskedOrEmpty(mx)) updates['mxtoolbox_api_key'] = mx.trim();
    if (us !== undefined && !isMaskedOrEmpty(us)) updates['urlscan_api_key'] = us.trim();
    if (ipi !== undefined && !isMaskedOrEmpty(ipi)) updates['ipinfo_api_key'] = ipi.trim();
    if (sho !== undefined && !isMaskedOrEmpty(sho)) updates['shodan_api_key'] = sho.trim();


    try {
      const res = await apiClient.updateSettings(token, { api_keys: updates });
      setSettingsData(res.settings);
      showNotification('API keys updated successfully.');
    } catch (err: any) {
      showNotification(err.message || 'Failed to save API keys', 'error');
    }
  };

  // ClamAV mirror update & progress polling
  const startClamavProgressPolling = () => {
    if (clamavPollIntervalRef.current) clearInterval(clamavPollIntervalRef.current);
    setIsUpdatingClamav(true);

    clamavPollIntervalRef.current = setInterval(async () => {
      try {
        const progRes = await apiClient.getClamavUpdateProgress(token);
        if (progRes && progRes.progress) {
          const p = progRes.progress;
          setClamavDownloadProgress(p);

          if (p.status === 'completed') {
            if (clamavPollIntervalRef.current) {
              clearInterval(clamavPollIntervalRef.current);
              clamavPollIntervalRef.current = null;
            }
            setIsUpdatingClamav(false);
            showNotification('ClamAV signature database downloaded and reloaded successfully.');
            fetchClamav();
            triggerBackgroundUpdateCheck(true);
          } else if (p.status === 'error') {
            if (clamavPollIntervalRef.current) {
              clearInterval(clamavPollIntervalRef.current);
              clamavPollIntervalRef.current = null;
            }
            setIsUpdatingClamav(false);
            showNotification(p.error || p.message || 'Definition download failed.', 'error');
          }
        }
      } catch (err) {
        console.error('Failed to poll ClamAV update progress:', err);
      }
    }, 500);
  };

  const handleUpdateClamav = async () => {
    setIsUpdatingClamav(true);
    setClamavDownloadProgress({
      is_downloading: true,
      status: 'connecting',
      current_file: 'Connecting to ClamAV CDN...',
      current_file_index: 0,
      total_files: 2,
      downloaded_bytes: 0,
      total_bytes: 0,
      percent: 5,
      speed_kbps: 0,
      message: 'Connecting to official ClamAV CDN (database.clamav.net)...',
      error: null,
    });

    try {
      const res = await apiClient.updateClamavMirror(token);
      if (res.success) {
        showNotification('ClamAV definition download started in background.');
        startClamavProgressPolling();
      } else {
        setIsUpdatingClamav(false);
        setClamavDownloadProgress((prev) => ({ ...prev, is_downloading: false, status: 'error', error: res.error }));
        showNotification(res.error || res.reload_message || 'Update failed to start.', 'error');
      }
    } catch (e: any) {
      setIsUpdatingClamav(false);
      setClamavDownloadProgress((prev) => ({ ...prev, is_downloading: false, status: 'error', error: e.message }));
      showNotification(e.message || 'Failed to update ClamAV definitions.', 'error');
    }
  };

  // ClamAV file upload with progress
  const handleUploadDefinition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadDefFile) return;
    setIsUploadingDef(true);
    setUploadProgress({ active: true, percent: 0, loaded: 0, total: uploadDefFile.size });
    try {
      const res = await apiClient.uploadClamavDefinitionsWithProgress(
        token,
        uploadDefFile,
        (percent, loaded, total) => {
          setUploadProgress({ active: true, percent, loaded, total });
        }
      );
      showNotification(`Installed ${res.filename} (${(res.size_bytes / 1024).toFixed(1)} KB).`);
      setUploadDefFile(null);
      setUploadProgress({ active: false, percent: 100, loaded: 0, total: 0 });
      fetchClamav();
    } catch (err: any) {
      showNotification(err.message || 'Failed to upload definition file', 'error');
      setUploadProgress({ active: false, percent: 0, loaded: 0, total: 0 });
    } finally {
      setIsUploadingDef(false);
    }
  };

  const handleInstallCommunityClamav = async (packKey: string) => {
    try {
      const resp = await fetch('/api/settings/clamav/community-signatures', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ pack: packKey })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        showNotification(`Successfully installed ${data.pack}! Database reloaded.`, 'success');
        fetchClamav();
      } else {
        showNotification(data.detail || data.error || 'Failed to install community pack.', 'error');
      }
    } catch (err: any) {
      showNotification(`Installation error: ${err.message}`, 'error');
    }
  };

  const handleImportCommunityYara = async (packId: string) => {
    try {
      const resp = await fetch(`/api/settings/yara/community-packs/${packId}/import`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        showNotification(data.message || `Imported community pack!`, 'success');
        fetchYara();
      } else {
        showNotification(data.detail || 'Failed to import community pack.', 'error');
      }
    } catch (err: any) {
      showNotification(`Import error: ${err.message}`, 'error');
    }
  };

  // YARA Modal Helpers
  const openNewYaraModal = () => {
    setEditingYaraId(null);
    setYaraName('');
    setYaraDesc('');
    setYaraSeverity('HIGH');
    setYaraFormat('ALL');
    setYaraText(`rule Custom_Suspicious_Pattern {
    meta:
        description = "Administrative custom indicator"
    strings:
        $s1 = "malicious_string_here" nocase
    condition:
        $s1
}`);
    setYaraValidation(null);
    setYaraError('');
    setShowYaraModal(true);
  };

  const openEditYaraModal = (rule: YaraRule) => {
    setEditingYaraId(rule.id);
    setYaraName(rule.name);
    setYaraDesc(rule.description || '');
    setYaraSeverity(rule.severity || 'HIGH');
    setYaraFormat(rule.target_format || 'ALL');
    setYaraText(rule.rule_text);
    setYaraValidation(null);
    setYaraError('');
    setShowYaraModal(true);
  };

  const handleValidateYara = async () => {
    setIsValidatingYara(true);
    try {
      const res = await apiClient.validateYaraSyntax(token, yaraText);
      setYaraValidation(res);
    } catch (err: any) {
      setYaraValidation({ valid: false, error: err.message || 'Validation error' });
    } finally {
      setIsValidatingYara(false);
    }
  };

  const handleSaveYaraRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setYaraError('');

    const payload = {
      name: yaraName,
      description: yaraDesc,
      severity: yaraSeverity,
      target_format: yaraFormat,
      rule_text: yaraText,
    };

    try {
      if (editingYaraId) {
        await apiClient.updateYaraRule(token, editingYaraId, payload);
        showNotification(`YARA rule '${yaraName}' updated and recompiled.`);
      } else {
        await apiClient.addYaraRule(token, payload);
        showNotification(`YARA rule '${yaraName}' added and compiled.`);
      }
      setShowYaraModal(false);
      fetchYara();
    } catch (err: any) {
      setYaraError(err.message || 'Failed to save YARA rule');
    }
  };

  const handleDeleteYaraRule = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this YARA rule?')) return;
    try {
      await apiClient.deleteYaraRule(token, ruleId);
      showNotification('YARA rule deleted.');
      fetchYara();
    } catch (e) {
      showNotification('Failed to delete rule.', 'error');
    }
  };

  const handleToggleYaraRule = async (ruleId: string, currentEnabled: boolean) => {
    try {
      await apiClient.toggleYaraRule(token, ruleId, !currentEnabled);
      fetchYara();
    } catch (e) {
      showNotification('Failed to toggle rule.', 'error');
    }
  };

  // Warninglist Modal Helpers
  const openNewWarningModal = () => {
    setEditingWarningId(null);
    setWarnName('');
    setWarnPattern('');
    setWarnIsRegex(false);
    setWarnSeverity('medium');
    setWarnDesc('');
    setWarningError('');
    setShowWarningModal(true);
  };

  const openEditWarningModal = (rule: WarningRule) => {
    setEditingWarningId(rule.id);
    setWarnName(rule.name || '');
    setWarnPattern(rule.pattern);
    setWarnIsRegex(rule.is_regex);
    setWarnSeverity(rule.severity as any);
    setWarnDesc(rule.description || '');
    setWarningError('');
    setShowWarningModal(true);
  };

  const handleSaveWarningRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setWarningError('');

    const payload = {
      name: warnName,
      pattern: warnPattern,
      is_regex: warnIsRegex,
      severity: warnSeverity,
      description: warnDesc,
    };

    try {
      if (editingWarningId) {
        await apiClient.updateWarningRule(token, editingWarningId, payload);
        showNotification('Warning rule updated successfully.');
      } else {
        await apiClient.addWarningRule(token, payload);
        showNotification('Warning rule created successfully.');
      }
      setShowWarningModal(false);
      fetchWarningRules();
    } catch (err: any) {
      setWarningError(err.message || 'Error saving rule');
    }
  };

  const handleDeleteWarningRule = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this warning rule?')) return;
    try {
      await apiClient.deleteWarningRule(token, ruleId);
      showNotification('Warning rule deleted.');
      fetchWarningRules();
    } catch (e) {
      showNotification('Failed to delete warning rule.', 'error');
    }
  };

  const handleToggleWarningRule = async (ruleId: string) => {
    try {
      await apiClient.toggleWarningRule(token, ruleId);
      fetchWarningRules();
    } catch (e) {
      showNotification('Failed to toggle warning rule.', 'error');
    }
  };

  // If not logged in, render clean, light Login View
  if (!token) {
    return (
      <div className="max-w-md mx-auto my-14 p-8 bg-white border border-slate-200 rounded-3xl shadow-xl animate-modal-fade">
        <div className="text-center mb-6">
          <div className="inline-flex p-3 bg-indigo-50 text-indigo-600 rounded-2xl mb-3 border border-indigo-100 shadow-sm">
            <span className="text-3xl">🔒</span>
          </div>
          <h2 className="text-2xl font-bold text-slate-900">Administrator Sign In</h2>
          <p className="text-sm text-slate-500 mt-1">
            Access security scanning controls, external network kill-switches, and threat signatures.
          </p>
        </div>

        {loginError && (
          <div className="mb-5 p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-700 text-xs flex items-center gap-2">
            <span>⚠️</span>
            <span>{loginError}</span>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
              Admin Username
            </label>
            <input
              type="text"
              required
              value={usernameInput}
              onChange={(e) => setUsernameInput(e.target.value)}
              className="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-sm text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              placeholder="admin"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
              Password
            </label>
            <input
              type="password"
              required
              value={passwordInput}
              onChange={(e) => setPasswordInput(e.target.value)}
              className="w-full bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-sm text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={isLoggingIn}
            className="w-full mt-2 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-sm rounded-xl shadow-md hover:shadow-indigo-600/25 transition-all flex items-center justify-center gap-2"
          >
            {isLoggingIn ? 'Authenticating...' : 'Sign In to Security Console'}
          </button>
        </form>

        <div className="mt-6 pt-5 border-t border-slate-100">
          <div className="flex items-center justify-between gap-3 p-3.5 bg-slate-50 rounded-2xl border border-slate-200">
            <div className="text-left">
              <div className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <span>📊</span> Telemetry &amp; Diagnostics Tab
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                {showTelemetryDiagnostics ? 'Currently Visible in workspace' : 'Currently Hidden (Default)'}
              </p>
            </div>
            <button
              type="button"
              onClick={() => handleToggleTelemetryDiagnostics(!showTelemetryDiagnostics)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl border transition-all cursor-pointer shadow-2xs ${
                showTelemetryDiagnostics
                  ? 'bg-indigo-600 hover:bg-indigo-700 text-white border-indigo-700'
                  : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
              }`}
            >
              {showTelemetryDiagnostics ? 'Hide Tab' : 'Show Tab'}
            </button>
          </div>

          <div className="flex items-center justify-between gap-3 p-3.5 bg-slate-50 rounded-2xl border border-slate-200 mt-2.5">
            <div className="text-left">
              <div className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <Github className="w-3.5 h-3.5 text-slate-700" />
                Automatic Update Checks
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                {checkForUpdates ? 'Notify on new GitHub releases' : 'Checks disabled (no popups)'}
              </p>
            </div>
            <button
              type="button"
              onClick={() => handleToggleCheckForUpdates(!checkForUpdates)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl border transition-all cursor-pointer shadow-2xs ${
                checkForUpdates
                  ? 'bg-indigo-600 hover:bg-indigo-700 text-white border-indigo-700'
                  : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
              }`}
            >
              {checkForUpdates ? 'Turn Off' : 'Turn On'}
            </button>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-slate-100 text-center">
          <button
            onClick={onBack}
            className="text-xs font-medium text-indigo-600 hover:text-indigo-800 transition-colors inline-flex items-center gap-1 cursor-pointer"
          >
            ← Return to Scanner Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-[80rem] mx-auto space-y-6 animate-overlay-fade">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-white border border-slate-200 p-6 rounded-3xl shadow-sm">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-indigo-50 text-indigo-600 rounded-2xl border border-indigo-100 shadow-sm text-2xl">
            ⚙️
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-slate-900">Security Administration & Policies</h1>
              <span className="px-2.5 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold rounded-full">
                Admin Authenticated
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Configure scanner behaviors, network egress policies, signature rules, and usage telemetry.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium rounded-xl transition-colors"
          >
            ← Back to Dashboard
          </button>
          <button
            onClick={handleLogout}
            className="px-4 py-2 bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-medium rounded-xl transition-colors"
          >
            Log Out
          </button>
        </div>
      </div>

      {/* Notification Toast */}
      {statusMsg && (
        <div
          className={`p-4 rounded-2xl text-sm flex items-center justify-between shadow-sm animate-modal-fade ${
            statusMsg.type === 'success'
              ? 'bg-emerald-50 border border-emerald-200 text-emerald-800'
              : 'bg-rose-50 border border-rose-200 text-rose-800'
          }`}
        >
          <div className="flex items-center gap-2">
            <span>{statusMsg.type === 'success' ? '✓' : '⚠️'}</span>
            <span>{statusMsg.text}</span>
          </div>
          <button onClick={() => setStatusMsg(null)} className="text-slate-400 hover:text-slate-600 text-lg">
            ×
          </button>
        </div>
      )}

      {/* Clean Light Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-3">
        {[
          { id: 'checks', label: '🛡️ Inspection Checks' },
          { id: 'ui_preferences', label: '🖥️ UI & Display' },
          { id: 'keys', label: '🔑 API Keys' },
          { id: 'external', label: '🌐 External Network Policies' },
          {
            id: 'clamav',
            label: updateCheck.newer_available ? '🦠 ClamAV Engine (Update Available)' : '🦠 ClamAV Engine',
            hasBadge: updateCheck.newer_available,
          },
          { id: 'yara', label: `🔍 YARA Rules (${yaraRules.length})` },
          { id: 'warninglist', label: `⚠️ Keyword & RegEx Watchlist (${warningRules.length})` },
          { id: 'hex_patterns', label: `🎯 File Formats & Patterns (${fileFormats.length})` },
          { id: 'cdr_policies', label: '🛡️ CDR & Sanitization Policies' },
          { id: 'evtx', label: '🪵 Windows Event Logs (EVTX)' },
          { id: 'time', label: '🕒 Time & Localization' },
          { id: 'statistics', label: '📊 Upload Statistics' },
          { id: 'history', label: '📋 Upload History' },
          { id: 'archive_passwords', label: `🔓 Archive Decryption (${archivePasswords.length})` },
          { id: 'cache', label: `⚡ Threat Intel Cache & Redis` },
          { id: 'audit_logs', label: `📜 Audit & System Logs (${auditCounts.TOTAL > 0 ? auditCounts.TOTAL : 'Live'})` },
          { id: 'api_docs', label: '⚡ API Integration Guide' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveTab(tab.id as any);
              if (tab.id === 'ui_preferences') fetchUiPreferences();
              if (tab.id === 'time') fetchTimeSettings();
              if (tab.id === 'clamav') fetchClamav();
              if ((tab.id === 'checks' || tab.id === 'keys' || tab.id === 'evtx') && !settingsData) fetchSettings();
              if (tab.id === 'external' && !externalPolicy) fetchExternalPolicy();
              if (tab.id === 'statistics' && !statisticsData) fetchStatistics();
              if (tab.id === 'history') fetchUploadHistory();
              if (tab.id === 'archive_passwords') fetchArchivePasswords();
              if (tab.id === 'cache') fetchCacheStats();
              if (tab.id === 'cdr_policies') fetchCdrPolicies();
              if (tab.id === 'audit_logs') fetchAuditLogs();
              if (tab.id === 'yara' && yaraRules.length === 0) fetchYara();
              if (tab.id === 'warninglist' && warningRules.length === 0) fetchWarningRules();
              if (tab.id === 'hex_patterns') {
                fetchFileFormats();
                fetchCustomPatterns();
              }
            }}
            className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 ${
              activeTab === tab.id
                ? 'bg-indigo-600 text-white shadow-sm shadow-indigo-600/20'
                : 'bg-white hover:bg-slate-100 text-slate-600 border border-slate-200'
            }`}
          >
            <span>{tab.label}</span>
            {tab.hasBadge && (
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            )}
          </button>
        ))}
      </div>

      {isLoading && (
        <div className="p-8 text-center text-slate-400 text-sm">
          Loading administrative configuration...
        </div>
      )}

      {/* TAB 1: Inspection Checks */}
      {activeTab === 'checks' && (
        !settingsData ? (
          <div className="bg-white border border-slate-200 rounded-3xl p-12 text-center shadow-sm">
            <div className="inline-block animate-spin w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full mb-3" />
            <p className="text-sm font-semibold text-slate-800">Loading inspection checks configuration...</p>
            <button
              onClick={fetchSettings}
              className="mt-4 px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors cursor-pointer"
            >
              🔄 Retry Loading Checks
            </button>
          </div>
        ) : (
        <div className="space-y-6">
          {/* Analysis Dashboard & Telemetry Display Card */}
          <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-lg">📊</span>
                  <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                    Telemetry &amp; Pipeline Diagnostics Tab
                  </h2>
                  <span
                    className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono ${
                      showTelemetryDiagnostics
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        : 'bg-slate-100 text-slate-600 border border-slate-200'
                    }`}
                  >
                    {showTelemetryDiagnostics ? 'VISIBLE' : 'HIDDEN (DEFAULT)'}
                  </span>
                </div>
                <p className="text-xs text-slate-500 max-w-3xl leading-relaxed">
                  Controls the visibility of the "Telemetry &amp; Diagnostics" tab in the file analysis dashboard.
                  When <strong>hidden (default)</strong>, the tab is concealed to prioritize analyst triage of security findings, threat intelligence, and IOC forensic graphs.
                  When <strong>visible</strong>, operators can inspect granular sub-step latency breakdown, Celery worker dispatch metrics, and pipeline execution durations.
                </p>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <button
                  type="button"
                  onClick={() => handleToggleTelemetryDiagnostics(!showTelemetryDiagnostics)}
                  className={`px-4 py-2.5 text-xs font-semibold rounded-xl border transition-all flex items-center gap-2.5 cursor-pointer shadow-sm ${
                    showTelemetryDiagnostics
                      ? 'bg-indigo-600 hover:bg-indigo-700 text-white border-indigo-700 shadow-indigo-600/20'
                      : 'bg-slate-50 hover:bg-slate-100 text-slate-700 border-slate-300'
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${showTelemetryDiagnostics ? 'bg-emerald-300 animate-pulse' : 'bg-slate-400'}`} />
                  <span>{showTelemetryDiagnostics ? '✓ Telemetry Tab: Visible' : '○ Telemetry Tab: Hidden'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Global Scanners */}
          <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
              <span>🌐</span> Global Scanner Engines
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { key: 'clamav_enabled', label: 'ClamAV Antivirus Daemon', desc: 'Scan uploaded files against signature database' },
                { key: 'yara_enabled', label: 'YARA Heuristics Engine', desc: 'Execute compiled active content and malware rules' },
                { key: 'virustotal_enabled', label: 'VirusTotal Threat Intel', desc: 'Query hashes and URLs via VirusTotal API' },
                { key: 'crowdstrike_enabled', label: 'CrowdStrike / Hybrid Analysis', desc: 'Query crowd-sourced sandbox verdicts & Falcon telemetry' },
                { key: 'circl_hashlookup_enabled', label: 'CIRCL Hashlookup', desc: 'NSRL and known benign / malware hash lookup' },
                { key: 'malwarebazaar_enabled', label: 'MalwareBazaar (abuse.ch)', desc: 'Check known malware sample registry and YARA signatures' },
                { key: 'shodan_enabled', label: 'Shodan Threat Intel', desc: 'Enrich hosts with exposed ports, service banners, and CVE correlation' },
              ].map((item) => {
                const enabled = settingsData.global_checks?.[item.key] ?? false;
                return (
                  <div
                    key={item.key}
                    onClick={() => handleToggleCheck('global_checks', item.key, enabled)}
                    className={`p-4 rounded-2xl border cursor-pointer transition-all ${
                      enabled
                        ? 'bg-emerald-50/60 border-emerald-200 shadow-sm'
                        : 'bg-slate-50 border-slate-200 opacity-60'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-xs text-slate-900">{item.label}</span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          enabled ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-200 text-slate-600'
                        }`}
                      >
                        {enabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500">{item.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Format Specific Checks */}
          <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
              <div>
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <span>📄</span> Format-Specific Deep Inspection Rules
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Configure granular inspection passes for each supported artifact type. Unchecking any rule prevents that analyzer step from executing.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {Object.entries(settingsData.format_checks || {}).map(([category, checks]: [string, any]) => {
                const formatMeta: Record<string, { label: string; icon: string; desc: string }> = {
                  executable: { label: 'Portable Executable (PE / EXE / DLL)', icon: '⚙️', desc: 'COFF headers, sections, imports, UPX packing, disassembly' },
                  elf: { label: 'Linux ELF Binaries', icon: '🐧', desc: 'ELF header, symbols, memory segments, security flags' },
                  macho: { label: 'macOS Mach-O Binaries', icon: '🍎', desc: 'Universal slices, load commands, code signing, entitlements' },
                  office: { label: 'Microsoft Office & ODF', icon: '📑', desc: 'VBA macros, stomping, ActiveX, OLE objects, DDE links' },
                  pdf: { label: 'Adobe PDF Documents', icon: '📄', desc: 'PDF streams, embedded JavaScript, launch actions, XFA' },
                  archive: { label: 'Archives (ZIP / 7Z / TAR)', icon: '📦', desc: 'Decompression bombs, path traversal, nested archives' },
                  apk: { label: 'Android Application (APK / AAB / DEX)', icon: '🤖', desc: 'Manifest XML, permissions, components, DEX bytecode, native .so, secrets' },
                  lnk: { label: 'Windows Shortcut (LNK)', icon: '🔗', desc: 'Header flags, target CLSIDs, LOLBins invocation, extra data, overlay' },
                  java: { label: 'Java (Source / Class / JAR)', icon: '☕', desc: 'Source AST heuristics, constant pool, dangerous JVM APIs, Java RATs, agents' },
                  jar: { label: 'Java Archives (JAR / WAR / EAR)', icon: '☕', desc: 'Manifest entries, bytecode reflection, dangerous APIs, RAT signatures' },
                  image: { label: 'Raster Images (PNG / JPG)', icon: '🖼️', desc: 'EXIF metadata, GPS geotags, steganography, C2PA AI provenance' },
                  email: { label: 'Email Messages (EML / MSG)', icon: '✉️', desc: 'MIME headers, SPF/DKIM/DMARC, tracking pixels, relay hops' },
                  script: { label: 'Scripts (PS1 / Bash / VBS)', icon: '📜', desc: 'Obfuscation, base64 stages, process spawning, cradles' },
                  svg_html: { label: 'Web Documents (SVG / HTML)', icon: '🌐', desc: 'Inline scripts, event handlers, external resources, iframes' },
                  text: { label: 'Plain Text & Configs', icon: '📝', desc: 'Discovered URIs, credential leaks, script triggers' },
                  extension: { label: 'Browser Extensions (CRX / XPI)', icon: '🧩', desc: 'Manifest permissions, background scripts, content scripts' },
                  domain: { label: 'Domain & DNS Infrastructure', icon: '🌍', desc: 'WHOIS/RDAP, DNS records, subdomains, SSL certificates' },
                  applescript: { label: 'AppleScript & OSA Scripts', icon: '🍏', desc: 'OSA decompilation, AppleEvents, keychain access' },
                  pcap: { label: 'PCAP / Network Forensics', icon: '📡', desc: 'Network flows, DNS, HTTP/FTP, TLS/JA3/JA4, carved payloads' },
                  evtx: { label: 'Windows Event Logs (EVTX)', icon: '🪵', desc: 'Security log clearing, ransomware, priv esc, LOLBins, PowerShell blocks' },
                };

                const meta = formatMeta[category] || { label: category.toUpperCase(), icon: '📁', desc: `${category} deep inspection rules` };
                const checkEntries = Object.entries(checks);
                const enabledCount = checkEntries.filter(([, v]) => Boolean(v)).length;

                // Group checks into 3 logical tiers
                const intelChecks = checkEntries.filter(([k]) => k.includes('virustotal') || k.includes('crowdstrike') || k.includes('clamav') || k.includes('yara') || k.includes('threatfox'));
                const payloadChecks = checkEntries.filter(([k]) => k.includes('macro') || k.includes('javascript') || k.includes('launch') || k.includes('tracking') || k.includes('cradle') || k.includes('process') || k.includes('activex') || k.includes('dde') || k.includes('events') || k.includes('keychain') || k.includes('permission'));
                const staticChecks = checkEntries.filter(([k]) => !intelChecks.some(([ik]) => ik === k) && !payloadChecks.some(([pk]) => pk === k));

                const groups = [
                  { title: '🔬 Static & Structural Inspection', items: staticChecks },
                  { title: '⚡ Payloads & Active Scripts', items: payloadChecks },
                  { title: '🛡️ Threat Intel & Signatures', items: intelChecks },
                ].filter(g => g.items.length > 0);

                return (
                  <div key={category} className="border border-slate-200 bg-slate-50/50 rounded-2xl p-4 flex flex-col justify-between shadow-2xs hover:shadow-xs transition-shadow">
                    <div>
                      {/* Card Header */}
                      <div className="pb-3 border-b border-slate-200 mb-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-bold text-xs text-slate-900 flex items-center gap-1.5 truncate" title={meta.label}>
                            <span>{meta.icon}</span>
                            <span className="truncate">{meta.label}</span>
                          </span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 font-mono ${
                            enabledCount === checkEntries.length
                              ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                              : enabledCount === 0
                              ? 'bg-rose-100 text-rose-800 border border-rose-200'
                              : 'bg-indigo-100 text-indigo-800 border border-indigo-200'
                          }`}>
                            {enabledCount}/{checkEntries.length} Active
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 mt-1 line-clamp-1">
                          {meta.desc}
                        </p>

                        {/* Batch Action Buttons */}
                        <div className="flex items-center gap-1.5 mt-2.5">
                          <button
                            type="button"
                            onClick={() => handleBatchToggleFormat(category, true)}
                            className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 cursor-pointer shadow-2xs"
                          >
                            Enable All
                          </button>
                          <button
                            type="button"
                            onClick={() => handleBatchToggleFormat(category, false)}
                            className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-white border border-slate-200 text-rose-700 hover:bg-rose-50 cursor-pointer shadow-2xs"
                          >
                            Disable All
                          </button>
                        </div>
                      </div>

                      {/* Grouped Check Items */}
                      <div className="space-y-3.5">
                        {groups.map(group => (
                          <div key={group.title} className="space-y-1.5">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block px-1">
                              {group.title}
                            </span>
                            <div className="space-y-1 bg-white/70 border border-slate-200/70 rounded-xl p-1.5 shadow-2xs">
                              {group.items.map(([checkKey, checkVal]: [string, any]) => {
                                const friendlyName = checkKey
                                  .replace(/^check_/, '')
                                  .replace(/_/g, ' ')
                                  .replace(/\b\w/g, l => l.toUpperCase());

                                return (
                                  <label
                                    key={checkKey}
                                    className="flex items-center justify-between gap-2.5 text-xs text-slate-700 hover:text-slate-900 cursor-pointer p-1.5 rounded-lg hover:bg-slate-100/80 transition-colors"
                                  >
                                    <span className="text-[11px] font-medium leading-tight">{friendlyName}</span>
                                    <input
                                      type="checkbox"
                                      checked={Boolean(checkVal)}
                                      onChange={() => handleToggleCheck(category, checkKey, Boolean(checkVal))}
                                      className="w-3.5 h-3.5 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500 cursor-pointer"
                                    />
                                  </label>
                                );
                              })}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Windows Event Log (EVTX) Timeline Monitored Event IDs */}
          <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-200">
              <div>
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <span>🪵</span> Windows Event Log (EVTX) Monitored Timeline Event IDs
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Select which Windows Security and Sysmon Event IDs are indexed and presented in the EVTX Forensic Timeline and Threat Dashboard.
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={handleSelectAllRecommendedEvtxIds}
                  className="px-2.5 py-1 text-[11px] font-semibold bg-indigo-50 text-indigo-700 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition-colors cursor-pointer"
                >
                  ✓ Select Recommended
                </button>
                <button
                  type="button"
                  onClick={handleClearAllEvtxIds}
                  className="px-2.5 py-1 text-[11px] font-semibold bg-slate-50 text-slate-600 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors cursor-pointer"
                >
                  Clear All
                </button>
                <button
                  type="button"
                  onClick={handleResetEvtxTimelineIds}
                  className="px-2.5 py-1 text-[11px] font-semibold bg-slate-50 text-slate-600 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors cursor-pointer"
                >
                  ↺ Reset Baseline
                </button>
              </div>
            </div>

            {/* Curated Preset Grid */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                    Curated Forensic & Threat Intelligence Presets
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono ml-2">
                    ({(settingsData?.evtx_timeline_event_ids || []).length} Event IDs currently monitored)
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setActiveTab('evtx')}
                  className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                >
                  Manage All 300+ Standard &amp; Extended Event IDs →
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {CURATED_EVTX_EVENTS.map((evt) => {
                  const activeIds: number[] = settingsData?.evtx_timeline_event_ids || [4624, 4625, 4672, 4688, 7045, 4698, 4720, 4728, 4732, 1102, 104, 4104, 5001, 1, 3];
                  const isChecked = activeIds.includes(evt.id);

                  return (
                    <label
                      key={evt.id}
                      className={`flex items-start gap-3 p-3 rounded-2xl border transition-all cursor-pointer select-none ${
                        isChecked
                          ? 'bg-indigo-50/50 border-indigo-200 shadow-2xs'
                          : 'bg-white border-slate-200 hover:bg-slate-50 opacity-75'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => handleToggleEvtxTimelineId(evt.id)}
                        className="mt-1 w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500 cursor-pointer shrink-0"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="font-mono text-xs font-bold text-slate-900 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                            ID {evt.id}
                          </span>
                          <span className="text-xs font-semibold text-slate-800 truncate" title={evt.name}>
                            {evt.name}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 mt-1 line-clamp-1" title={evt.desc}>
                          {evt.desc}
                        </p>
                        <div className="mt-1 flex items-center gap-1.5">
                          <span className="text-[10px] font-semibold text-slate-500 bg-white border border-slate-200 px-1.5 py-0.5 rounded-full">
                            {evt.category}
                          </span>
                          {evt.severity && (
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-full ${
                              evt.severity === 'critical' ? 'bg-rose-100 text-rose-800 border border-rose-200' :
                              evt.severity === 'high' ? 'bg-amber-100 text-amber-800 border border-amber-200' :
                              evt.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 border border-yellow-200' :
                              'bg-blue-100 text-blue-800 border border-blue-200'
                            }`}>
                              {evt.severity}
                            </span>
                          )}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* Custom Monitored Event IDs */}
            <div className="pt-3 border-t border-slate-100 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Custom Monitored Event IDs
                </span>
                <form onSubmit={handleAddCustomEvtxId} className="flex items-center gap-2">
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    value={customEvtxIdInput}
                    onChange={(e) => setCustomEvtxIdInput(e.target.value)}
                    placeholder="e.g. 4738, 4634, 4673"
                    className="w-44 px-3 py-1.5 text-xs bg-slate-50 border border-slate-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-colors cursor-pointer shadow-2xs"
                  >
                    + Add Event ID
                  </button>
                </form>
              </div>

              {/* Show chips for any IDs currently monitored that are NOT in KNOWN_EVTX_EVENTS */}
              {(() => {
                const activeIds: number[] = settingsData?.evtx_timeline_event_ids || [4624, 4625, 4672, 4688, 7045, 4698, 4720, 4728, 4732, 1102, 104, 4104, 5001, 1, 3];
                const knownIds = new Set(KNOWN_EVTX_EVENTS.map(k => k.id));
                const customIds = activeIds.filter(id => !knownIds.has(id));

                if (customIds.length === 0) {
                  return (
                    <p className="text-[11px] text-slate-400 italic">
                      No custom Event IDs registered. Type an Event ID above to include non-standard audit channels in the timeline.
                    </p>
                  );
                }

                return (
                  <div className="flex flex-wrap gap-2">
                    {customIds.map((id) => (
                      <span
                        key={id}
                        className="inline-flex items-center gap-1.5 bg-indigo-50 border border-indigo-200 text-indigo-800 text-xs font-mono font-bold px-2.5 py-1 rounded-xl"
                      >
                        <span>ID {id}</span>
                        <button
                          type="button"
                          onClick={() => handleToggleEvtxTimelineId(id)}
                          className="text-indigo-400 hover:text-rose-600 transition-colors cursor-pointer ml-1"
                          title="Remove Event ID"
                        >
                          ✕
                        </button>
                      </span>
                    ))}
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
        )
      )}

      {/* TAB: UI & Display Preferences */}
      {activeTab === 'ui_preferences' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-7 shadow-sm space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
              <div>
                <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <span>🖥️</span> User Interface &amp; Dashboard Display Preferences
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Customize the visibility of analysis dashboard views, diagnostic telemetry, and analyst presentation modules.
                </p>
              </div>
            </div>

            {/* Telemetry & Diagnostics Toggle Card */}
            <div className="p-5 rounded-2xl border border-slate-200 bg-slate-50/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1.5 max-w-2xl">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-xs text-slate-900">
                    Telemetry &amp; Pipeline Diagnostics Tab
                  </span>
                  <span
                    className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono ${
                      showTelemetryDiagnostics
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                        : 'bg-slate-200 text-slate-600'
                    }`}
                  >
                    {showTelemetryDiagnostics ? 'ENABLED (VISIBLE)' : 'DISABLED (HIDDEN BY DEFAULT)'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  Controls whether the <strong>Telemetry &amp; Diagnostics</strong> tab is rendered inside the file analysis workspace.
                  When disabled (default), the diagnostics tab is hidden to maintain a streamlined security and threat-hunting interface.
                  When enabled, analysts can inspect pipeline execution timings, Celery background worker dispatches, and step-by-step latency diagnostics.
                </p>
              </div>

              <div className="shrink-0 flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => handleToggleTelemetryDiagnostics(!showTelemetryDiagnostics)}
                  className={`px-5 py-2.5 rounded-xl text-xs font-semibold border transition-all flex items-center gap-2 cursor-pointer shadow-sm ${
                    showTelemetryDiagnostics
                      ? 'bg-indigo-600 hover:bg-indigo-700 text-white border-indigo-700 shadow-indigo-600/20'
                      : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
                  }`}
                >
                  <span className={`w-2.5 h-2.5 rounded-full ${showTelemetryDiagnostics ? 'bg-emerald-400' : 'bg-slate-400'}`} />
                  <span>{showTelemetryDiagnostics ? '✓ Diagnostics Tab Visible (Click to Hide)' : '○ Diagnostics Tab Hidden (Click to Show)'}</span>
                </button>
              </div>
            </div>

            {/* GitHub Version & Automatic Update Checks Toggle Card */}
            <div className="p-5 rounded-2xl border border-slate-200 bg-slate-50/60 flex flex-col gap-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-xs text-slate-900 flex items-center gap-1.5">
                      <Github className="w-3.5 h-3.5 text-slate-700" />
                      Automatic GitHub Version &amp; Update Checks
                    </span>
                    <span
                      className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full font-mono ${
                        checkForUpdates
                          ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                          : 'bg-slate-200 text-slate-600'
                      }`}
                    >
                      {checkForUpdates ? 'ENABLED (CHECK ON STARTUP)' : 'DISABLED (NO POPUPS)'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Automatically checks GitHub for newer FileSanitizer releases and security updates when loading the application.
                    When a newer version exists, a notification popup modal will appear with release details, changelog, and direct GitHub links.
                    Disable this option if you want to turn off automatic update checks and avoid update popups.
                  </p>
                </div>

                <div className="shrink-0 flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => handleToggleCheckForUpdates(!checkForUpdates)}
                    className={`px-5 py-2.5 rounded-xl text-xs font-semibold border transition-all flex items-center gap-2 cursor-pointer shadow-sm ${
                      checkForUpdates
                        ? 'bg-indigo-600 hover:bg-indigo-700 text-white border-indigo-700 shadow-indigo-600/20'
                        : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300'
                    }`}
                  >
                    <span className={`w-2.5 h-2.5 rounded-full ${checkForUpdates ? 'bg-emerald-400' : 'bg-slate-400'}`} />
                    <span>{checkForUpdates ? '✓ Auto-Check Enabled (Click to Turn Off)' : '○ Auto-Check Disabled (Click to Turn On)'}</span>
                  </button>
                </div>
              </div>

              {/* Manual Update Check Toolbar */}
              <div className="pt-3 border-t border-slate-200/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleManualCheckUpdates}
                    disabled={isCheckingUpdates}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-white hover:bg-slate-100 text-slate-700 font-semibold text-xs border border-slate-300 rounded-xl transition-all shadow-2xs disabled:opacity-50 cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 text-indigo-600 ${isCheckingUpdates ? 'animate-spin' : ''}`} />
                    <span>{isCheckingUpdates ? 'Checking GitHub...' : 'Check for Updates Now'}</span>
                  </button>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Current: v{APP_VERSION}
                  </span>
                </div>

                {updateCheckStatus && (
                  <div className="flex items-center gap-2 text-xs">
                    {updateCheckStatus.type === 'has_update' ? (
                      <div className="flex items-center gap-2 bg-emerald-50 border border-emerald-200 text-emerald-800 px-3 py-1.5 rounded-xl font-medium">
                        <Sparkles className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
                        <span>{updateCheckStatus.message}</span>
                        <button
                          type="button"
                          onClick={() => {
                            setUpdateModalInfo(updateCheckStatus.details);
                            setShowUpdateModalFromSettings(true);
                          }}
                          className="underline font-bold hover:text-emerald-900 cursor-pointer ml-1"
                        >
                          View Details &rarr;
                        </button>
                      </div>
                    ) : updateCheckStatus.type === 'success' ? (
                      <div className="flex items-center gap-1.5 text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1 rounded-xl">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{updateCheckStatus.message}</span>
                      </div>
                    ) : updateCheckStatus.type === 'warning' ? (
                      <div className="flex items-center gap-1.5 text-amber-700 bg-amber-50 border border-amber-200 px-3 py-1 rounded-xl">
                        <AlertCircle className="w-3.5 h-3.5" />
                        <span>{updateCheckStatus.message}</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-rose-700 bg-rose-50 border border-rose-200 px-3 py-1 rounded-xl">
                        <AlertCircle className="w-3.5 h-3.5" />
                        <span>{updateCheckStatus.message}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Quick Navigation to Time & Localization */}
            <div className="p-5 rounded-2xl border border-indigo-100 bg-indigo-50/40 flex items-center justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-bold text-indigo-900 flex items-center gap-1.5">
                  <span>🕒</span> Time &amp; Timestamp Normalization
                </span>
                <p className="text-xs text-indigo-700">
                  Configure 24-hour / 12-hour clock, UTC / local timezone offset, and timestamp precision across all event timelines.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setActiveTab('time');
                  fetchTimeSettings();
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl transition-colors cursor-pointer shrink-0 shadow-sm"
              >
                Configure Time Settings →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: API Keys */}
      {activeTab === 'keys' && (
        !settingsData ? (
          <div className="bg-white border border-slate-200 rounded-3xl p-12 text-center shadow-sm">
            <div className="inline-block animate-spin w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full mb-3" />
            <p className="text-sm font-semibold text-slate-800">Loading API keys configuration...</p>
            <button
              onClick={fetchSettings}
              className="mt-4 px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors cursor-pointer"
            >
              🔄 Retry Loading Keys
            </button>
          </div>
        ) : (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
          <div className="mb-6">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <span>🔑</span> Third-Party Threat Intelligence Keys
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              Add your enterprise or community API keys to enable live reputation checks for discovered URLs and file hashes.
            </p>
          </div>

          <form onSubmit={handleSaveApiKeys} className="space-y-6 max-w-3xl">
            {/* VirusTotal Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>🛡️</span> VirusTotal v3 API Key
                </label>
                <a
                  href="https://www.virustotal.com/gui/user/apiKey"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Get Free Key ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="vt_api_key_input"
                  type="text"
                  name="virustotal_api_key"
                  defaultValue={settingsData.api_keys?.virustotal_api_key || ''}
                  placeholder="64-character VirusTotal API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('virustotal', 'vt_api_key_input')}
                  disabled={keyVerification['virustotal']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['virustotal']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Used for automated file hash querying, community risk score, engine breakdown, and URL reputation intelligence.
              </p>
              {keyVerification['virustotal'] && !keyVerification['virustotal'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['virustotal'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['virustotal'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['virustotal'].message}</span>
                </div>
              )}
            </div>

            {/* Abuse.ch URLhaus Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>☣️</span> Abuse.ch URLhaus API Key
                </label>
                <a
                  href="https://urlhaus.abuse.ch/api/"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  URLhaus Docs ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="urlhaus_api_key_input"
                  type="text"
                  name="urlhaus_api_key"
                  defaultValue={settingsData.api_keys?.urlhaus_api_key || ''}
                  placeholder="Abuse.ch Auth-Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('urlhaus', 'urlhaus_api_key_input')}
                  disabled={keyVerification['urlhaus']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['urlhaus']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Queries the Abuse.ch community database for active malware download endpoints and C2 botnet servers.
              </p>
              {keyVerification['urlhaus'] && !keyVerification['urlhaus'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['urlhaus'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['urlhaus'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['urlhaus'].message}</span>
                </div>
              )}
            </div>

            {/* Google Safe Browsing Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>🔍</span> Google Safe Browsing v4 Key
                </label>
                <a
                  href="https://developers.google.com/safe-browsing/v4/get-started"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Console ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="safebrowsing_api_key_input"
                  type="text"
                  name="safe_browsing_api_key"
                  defaultValue={settingsData.api_keys?.safe_browsing_api_key || ''}
                  placeholder="Google Cloud Safe Browsing API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('safebrowsing', 'safebrowsing_api_key_input')}
                  disabled={keyVerification['safebrowsing']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['safebrowsing']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Checks URLs against Google's constantly updated lists of suspected phishing, malware, and social engineering sites.
              </p>
              {keyVerification['safebrowsing'] && !keyVerification['safebrowsing'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['safebrowsing'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['safebrowsing'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['safebrowsing'].message}</span>
                </div>
              )}
            </div>

            {/* AbuseIPDB API Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>🌐</span> AbuseIPDB v2 API Key
                </label>
                <a
                  href="https://www.abuseipdb.com/pricing"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Get Free Key ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="abuseipdb_api_key_input"
                  type="text"
                  name="abuseipdb_api_key"
                  defaultValue={settingsData.api_keys?.abuseipdb_api_key || ''}
                  placeholder="80-character AbuseIPDB API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('abuseipdb', 'abuseipdb_api_key_input')}
                  disabled={keyVerification['abuseipdb']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['abuseipdb']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Queries IP reputation, attack report counts, abuse confidence scores, and ISP attribution for resolved domain hosts.
              </p>
              {keyVerification['abuseipdb'] && !keyVerification['abuseipdb'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['abuseipdb'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['abuseipdb'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['abuseipdb'].message}</span>
                </div>
              )}
            </div>

            {/* AlienVault OTX Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>👽</span> AlienVault OTX (Open Threat Exchange) Key
                </label>
                <a
                  href="https://otx.alienvault.com/"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  OTX Community ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="alienvault_otx_api_key_input"
                  type="text"
                  name="alienvault_otx_api_key"
                  defaultValue={settingsData.api_keys?.alienvault_otx_api_key || ''}
                  placeholder="AlienVault OTX API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('alienvault_otx', 'alienvault_otx_api_key_input')}
                  disabled={keyVerification['alienvault_otx']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['alienvault_otx']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Queries threat pulses, adversary campaign tags, and IOC associations across the global Open Threat Exchange.
              </p>
              {keyVerification['alienvault_otx'] && !keyVerification['alienvault_otx'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['alienvault_otx'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['alienvault_otx'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['alienvault_otx'].message}</span>
                </div>
              )}
            </div>

            {/* Hybrid Analysis (Falcon Sandbox) API Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>🦅</span> Hybrid Analysis (Falcon Sandbox) Community API Key
                </label>
                <a
                  href="https://hybrid-analysis.com/docs/api/v2"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Get Free Key ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="hybrid_analysis_api_key_input"
                  type="text"
                  name="hybrid_analysis_api_key"
                  defaultValue={settingsData.api_keys?.hybrid_analysis_api_key || ''}
                  placeholder="Falcon Sandbox API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('hybridanalysis', 'hybrid_analysis_api_key_input')}
                  disabled={keyVerification['hybridanalysis']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['hybridanalysis']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Queries CrowdStrike / Falcon Sandbox hash intelligence, threat scores, vx_family classification, and AV detection rates.
              </p>
              {keyVerification['hybridanalysis'] && !keyVerification['hybridanalysis'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['hybridanalysis'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['hybridanalysis'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['hybridanalysis'].message}</span>
                </div>
              )}
            </div>

            {/* MXToolbox API Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>📬</span> MXToolbox API Key
                </label>
                <a
                  href="https://mxtoolbox.com/api"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  MXToolbox API ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="mxtoolbox_api_key_input"
                  type="text"
                  name="mxtoolbox_api_key"
                  defaultValue={settingsData.api_keys?.mxtoolbox_api_key || ''}
                  placeholder="MXToolbox API Key / Token"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('mxtoolbox', 'mxtoolbox_api_key_input')}
                  disabled={keyVerification['mxtoolbox']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['mxtoolbox']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Performs deep mail exchange diagnostics, SPF syntax verification, DKIM selector health, and queries 100+ DNS RBL blacklists for email domains.
              </p>
              {keyVerification['mxtoolbox'] && !keyVerification['mxtoolbox'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['mxtoolbox'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['mxtoolbox'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['mxtoolbox'].message}</span>
                </div>
              )}
            </div>

            {/* urlscan.io API Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>🔍</span> urlscan.io API Key
                </label>
                <a
                  href="https://urlscan.io/user/signup"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Get Free API Key ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="urlscan_api_key_input"
                  type="text"
                  name="urlscan_api_key"
                  defaultValue={settingsData.api_keys?.urlscan_api_key || ''}
                  placeholder="urlscan.io API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('urlscan', 'urlscan_api_key_input')}
                  disabled={keyVerification['urlscan']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['urlscan']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Scans URLs for malicious content, phishing pages, and suspicious redirects. Used for cross-referencing discovered URLs against urlscan.io threat intelligence database.
              </p>
              {keyVerification['urlscan'] && !keyVerification['urlscan'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['urlscan'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['urlscan'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['urlscan'].message}</span>
                </div>
              )}
            </div>

            {/* IPinfo.io Token */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>📍</span> IPinfo.io Access Token
                </label>
                <a
                  href="https://ipinfo.io/signup"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Get Token (50k/mo free) ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="ipinfo_api_key_input"
                  type="text"
                  name="ipinfo_api_key"
                  defaultValue={settingsData.api_keys?.ipinfo_api_key || ''}
                  placeholder="IPinfo.io Token (Optional - Works without token up to daily limit)"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('ipinfo', 'ipinfo_api_key_input')}
                  disabled={keyVerification['ipinfo']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['ipinfo']?.loading ? '⚡ Testing...' : '⚡ Test Connection'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Enriches sender IPs and hops with Autonomous System (ASN), ISP organization, city, country, and privacy detection (VPN, Tor, Proxy, Hosting).
              </p>
              {keyVerification['ipinfo'] && !keyVerification['ipinfo'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['ipinfo'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['ipinfo'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['ipinfo'].message}</span>
                </div>
              )}
            </div>

            {/* Shodan API Key */}
            <div className="p-4 bg-slate-50/80 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-800 flex items-center gap-1.5">
                  <span>🪐</span> Shodan Host Intelligence & CVE Search API Key
                </label>
                <a
                  href="https://account.shodan.io/"
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-indigo-600 hover:underline font-medium"
                >
                  Get Shodan API Key ↗
                </a>
              </div>
              <div className="flex gap-2">
                <input
                  id="shodan_api_key_input"
                  type="text"
                  name="shodan_api_key"
                  defaultValue={settingsData.api_keys?.shodan_api_key || ''}
                  placeholder="32-character Shodan API Key"
                  className="flex-1 bg-white border border-slate-300 rounded-xl px-4 py-2 text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('shodan', 'shodan_api_key_input')}
                  disabled={keyVerification['shodan']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold rounded-xl border border-slate-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['shodan']?.loading ? '⚡ Testing...' : '⚡ Verify Key'}
                </button>
              </div>
              <p className="text-[11px] text-slate-500">
                Correlates target IP addresses and hostnames against Shodan's global repository to enumerate open ports, running services, software banners, and verified CVE vulnerabilities.
              </p>
              {keyVerification['shodan'] && !keyVerification['shodan'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['shodan'].valid
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['shodan'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['shodan'].message}</span>
                </div>
              )}
            </div>

            {/* Public RDAP / WHOIS Service */}
            <div className="p-4 bg-emerald-50/50 border border-emerald-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-emerald-950 flex items-center gap-1.5">
                  <span>🏛️</span> Public RDAP / WHOIS Directory (IANA / ARIN / RIPE)
                </label>
                <span className="text-[10px] bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded-full font-bold">
                  Zero-Key REST Protocol
                </span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <p className="text-[11px] text-slate-600 flex-1">
                  Registration Data Access Protocol (RFC 7482 / RFC 9083). Queries open registries for domain creation dates, age (&lt;30 days alert), and official registrars with zero API keys required.
                </p>
                <button
                  type="button"
                  onClick={() => handleVerifyApiKey('rdap', '')}
                  disabled={keyVerification['rdap']?.loading}
                  className="px-3.5 py-2 bg-white hover:bg-emerald-50 text-emerald-800 text-xs font-semibold rounded-xl border border-emerald-300 transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-2xs"
                >
                  {keyVerification['rdap']?.loading ? '⚡ Testing...' : '⚡ Test RDAP Service'}
                </button>
              </div>
              {keyVerification['rdap'] && !keyVerification['rdap'].loading && (
                <div className={`p-2.5 rounded-xl text-xs flex items-center gap-2 border ${
                  keyVerification['rdap'].valid
                    ? 'bg-emerald-100/70 text-emerald-900 border-emerald-300'
                    : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <span>{keyVerification['rdap'].valid ? '✅' : '❌'}</span>
                  <span className="font-medium">{keyVerification['rdap'].message}</span>
                </div>
              )}
            </div>

            <button
              type="submit"
              className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-xl shadow-md transition-all cursor-pointer"
            >
              Save API Keys
            </button>
          </form>

          {/* Dangerous URL Extensions Management */}
          <div className="mt-10 pt-8 border-t border-slate-200">
            <div className="mb-4">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-lg">🚫</span>
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                  Dangerous URL File Extensions
                </h3>
                <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 font-semibold">
                  {dangerousExtensions.length} classified
                </span>
              </div>
              <p className="text-xs text-slate-600">
                URLs targeting executable payloads or installer binaries ending with these extensions will be classified as <strong className="text-slate-800">HIGH RISK</strong>.
                You can add custom file extensions or remove existing ones.
              </p>
            </div>

            {/* Active Extension Chips */}
            <div className="flex flex-wrap gap-2 p-4 bg-slate-50 border border-slate-200 rounded-2xl mb-4 min-h-[56px] items-center">
              {dangerousExtensions.length > 0 ? (
                dangerousExtensions.map((ext) => (
                  <span
                    key={ext}
                    className="inline-flex items-center gap-1.5 px-3 py-1 bg-white border border-slate-300 rounded-full text-xs font-mono font-semibold text-slate-800 shadow-2xs hover:border-rose-400 group transition-all"
                  >
                    <span>{ext}</span>
                    <button
                      type="button"
                      onClick={() => handleDeleteExtension(ext)}
                      className="text-slate-400 group-hover:text-rose-600 font-bold hover:bg-rose-50 rounded-full px-1 transition-colors cursor-pointer"
                      title={`Remove ${ext}`}
                    >
                      ×
                    </button>
                  </span>
                ))
              ) : (
                <span className="text-xs text-slate-400 italic">No dangerous extensions configured.</span>
              )}
            </div>

            {/* Add Extension Form */}
            <form onSubmit={handleAddExtension} className="flex items-center gap-2 max-w-md">
              <input
                type="text"
                value={newExtInput}
                onChange={(e) => setNewExtInput(e.target.value)}
                placeholder="e.g. .apk, .bin, .dmg, .iso"
                className="flex-1 bg-white border border-slate-300 rounded-xl px-3.5 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
              />
              <button
                type="submit"
                disabled={isAddingExt || !newExtInput.trim()}
                className="px-4 py-2 bg-slate-900 hover:bg-indigo-600 text-white text-xs font-semibold rounded-xl shadow-xs transition-colors cursor-pointer disabled:opacity-50"
              >
                {isAddingExt ? 'Adding...' : '+ Add Extension'}
              </button>
            </form>
          </div>
        </div>
        )
      )}

      {/* TAB 3: External Network Policies */}
      {activeTab === 'external' && (
        !externalPolicy ? (
          <div className="bg-white border border-slate-200 rounded-3xl p-12 text-center shadow-sm">
            <div className="inline-block animate-spin w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full mb-3" />
            <p className="text-sm font-semibold text-slate-800">Loading external network policies...</p>
            <button
              onClick={fetchExternalPolicy}
              className="mt-4 px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors cursor-pointer"
            >
              🔄 Retry Loading Policies
            </button>
          </div>
        ) : (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <span>🌐</span> Outbound Network Isolation & Kill-Switches
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Control whether the application touches external web endpoints. You can disable all outbound requests for full air-gap compliance, or toggle specific network probes individually.
                </p>
              </div>

              {/* Master Switch */}
              <button
                onClick={() => handleToggleExternal('allow_all_external', externalPolicy.allow_all_external)}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shadow-sm ${
                  externalPolicy.allow_all_external
                    ? 'bg-emerald-600 text-white hover:bg-emerald-700'
                    : 'bg-rose-600 text-white hover:bg-rose-700'
                }`}
              >
                {externalPolicy.allow_all_external ? 'ALL EXTERNAL: ALLOWED' : 'AIR-GAP MODE: ALL BLOCKED'}
              </button>
            </div>

            {!externalPolicy.allow_all_external && (
              <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl mb-6 text-amber-800 text-xs flex items-center gap-2">
                <span className="text-base">⚠️</span>
                <span>
                  <strong>Air-Gap Compliance Mode Active:</strong> All outbound HTTP requests, screenshots, TLS inspections, threat intel lookups, and geocoding queries are strictly blocked.
                </span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                {
                  key: 'allow_http_status_and_redirects' as const,
                  label: 'HTTP Status & Redirect Following',
                  desc: 'Sends lightweight HTTP requests to check if URLs are reachable and follow destination redirects.',
                },
                {
                  key: 'allow_screenshots' as const,
                  label: 'Headless Browser URL Screenshots',
                  desc: 'Uses the isolated Chromium sandbox to take visual snapshots of discovered external web pages.',
                },
                {
                  key: 'allow_tls_inspection' as const,
                  label: 'Remote TLS / HTTPS Certificate Inspection',
                  desc: 'Performs live SSL/TLS handshake to extract certificate issuer, expiration, and cipher details.',
                },
                {
                  key: 'allow_threat_intel_lookups' as const,
                  label: 'External Threat Intelligence Feeds',
                  desc: 'Sends URL and hash queries to VirusTotal, URLhaus, and Google Safe Browsing APIs.',
                },
                {
                  key: 'allow_geolocation_lookups' as const,
                  label: 'Online Reverse Geocoding (Nominatim OpenStreetMap)',
                  desc: 'Translates GPS coordinates to city and country via OpenStreetMap API (falls back to offline database when disabled).',
                },
                {
                  key: 'allow_clamav_official_updates' as const,
                  label: 'Official ClamAV Mirror Updates',
                  desc: 'Downloads daily.cvd and main.cvd definitions from official ClamAV mirror servers.',
                },
              ].map((item) => {
                const isEnabled = externalPolicy[item.key];
                const isAirgapped = !externalPolicy.allow_all_external;
                return (
                  <div
                    key={item.key}
                    onClick={() => {
                      if (!isAirgapped) handleToggleExternal(item.key, isEnabled);
                    }}
                    className={`p-4 rounded-2xl border transition-all ${
                      isAirgapped
                        ? 'bg-slate-50 border-slate-200 opacity-50 cursor-not-allowed'
                        : isEnabled
                        ? 'bg-emerald-50/50 border-emerald-200 hover:border-emerald-300 cursor-pointer shadow-sm'
                        : 'bg-slate-50 border-slate-200 opacity-60 hover:opacity-80 cursor-pointer'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-xs text-slate-900">{item.label}</span>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          isEnabled && !isAirgapped
                            ? 'bg-emerald-100 text-emerald-800'
                            : 'bg-slate-200 text-slate-600'
                        }`}
                      >
                        {isEnabled && !isAirgapped ? 'ALLOWED' : 'BLOCKED'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 leading-relaxed">{item.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
        )
      )}

      {/* TAB 4: ClamAV Engine */}
      {activeTab === 'clamav' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-4 mb-6 pb-6 border-b border-slate-100">
              <div>
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <span>🦠</span> Antivirus Engine & Definition Status
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Status of the internal ClamAV daemon and installed threat signatures.
                </p>
              </div>

              <div className="flex items-center gap-2.5 flex-wrap">
                <button
                  onClick={() => triggerBackgroundUpdateCheck(true)}
                  disabled={updateCheck.loading}
                  className={`px-3.5 py-2 text-xs font-semibold rounded-xl border transition-all flex items-center gap-2 ${
                    updateCheck.loading
                      ? 'bg-indigo-50 border-indigo-300 text-indigo-700 shadow-sm animate-pulse'
                      : 'bg-white hover:bg-slate-50 border-slate-300 text-slate-700 shadow-xs'
                  }`}
                  title="Query official ClamAV mirror and DNS for newest definitions"
                >
                  {updateCheck.loading ? (
                    <>
                      <svg className="animate-spin h-3.5 w-3.5 text-indigo-600" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                      </svg>
                      <span>Checking Mirror Online...</span>
                    </>
                  ) : (
                    <>
                      <span>🔍</span>
                      <span>Check for Updates</span>
                    </>
                  )}
                </button>

                <button
                  onClick={handleUpdateClamav}
                  disabled={isUpdatingClamav || clamavDownloadProgress.is_downloading}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-sm transition-all flex items-center gap-2"
                >
                  {isUpdatingClamav || clamavDownloadProgress.is_downloading ? (
                    <>
                      <svg className="animate-spin h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                      </svg>
                      <span>Downloading Definitions...</span>
                    </>
                  ) : (
                    <>
                      <span>⚡</span>
                      <span>Sync Definitions Now</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Checking Status Banner (High Visibility) */}
            {updateCheck.loading && (
              <div className="mb-6 p-4 bg-indigo-50/95 border border-indigo-200 rounded-2xl flex items-center justify-between gap-4 shadow-sm animate-pulse">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center shrink-0 shadow-md">
                    <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                    </svg>
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-indigo-950 uppercase tracking-wide flex items-center gap-1.5">
                      <span>📡</span> Checking Official ClamAV Mirrors Online...
                    </h4>
                    <p className="text-[11px] text-indigo-700 mt-0.5">
                      Querying Cisco Talos DNS records (<code className="font-mono font-bold">current.cvd.clamav.net</code>) and ClamAV CDN to inspect the latest signature releases.
                    </p>
                  </div>
                </div>
                <span className="text-[11px] font-mono font-bold text-indigo-700 bg-indigo-100/90 px-3 py-1 rounded-full border border-indigo-300 shrink-0">
                  Querying...
                </span>
              </div>
            )}

            {/* ClamAV Download Progress Bar */}
            {(isUpdatingClamav || clamavDownloadProgress.is_downloading) && (
              <div className="mb-6 p-5 bg-white border border-indigo-200 rounded-3xl shadow-sm space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-2xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 text-lg shadow-xs shrink-0">
                      <svg className="animate-spin h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                      </svg>
                    </div>
                    <div>
                      <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                        <span>📥</span> Downloading ClamAV Definition Database
                      </h3>
                      <p className="text-[11px] text-slate-500 mt-0.5 font-mono">
                        {clamavDownloadProgress.message || 'Connecting to official ClamAV mirror (database.clamav.net)...'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-mono font-bold text-indigo-700 bg-indigo-50 px-3 py-1 rounded-xl border border-indigo-200">
                      {Math.round(clamavDownloadProgress.percent || 5)}%
                    </span>
                  </div>
                </div>

                {/* Real-time Progress Bar */}
                <div className="space-y-2">
                  <div className="w-full bg-slate-100 rounded-full h-3.5 overflow-hidden border border-slate-200 p-0.5">
                    <div
                      className="bg-gradient-to-r from-indigo-500 via-indigo-600 to-purple-600 h-full rounded-full transition-all duration-300 ease-out relative"
                      style={{ width: `${Math.max(5, Math.min(100, clamavDownloadProgress.percent || 5))}%` }}
                    >
                      <div className="absolute inset-0 bg-white/30 animate-pulse rounded-full" />
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>
                      {clamavDownloadProgress.current_file ? (
                        <span>Downloading: <strong className="text-slate-800">{clamavDownloadProgress.current_file}</strong></span>
                      ) : (
                        'Establishing CDN stream connection...'
                      )}
                    </span>
                    <span>
                      {clamavDownloadProgress.downloaded_bytes > 0 && clamavDownloadProgress.total_bytes > 0 ? (
                        <span className="text-slate-700 font-semibold">
                          {(clamavDownloadProgress.downloaded_bytes / 1048576).toFixed(1)} MB / {(clamavDownloadProgress.total_bytes / 1048576).toFixed(1)} MB
                        </span>
                      ) : (
                        `${Math.round(clamavDownloadProgress.percent || 5)}%`
                      )}
                      {clamavDownloadProgress.speed_kbps > 0 && (
                        <span className="text-indigo-600 ml-2 font-medium">
                          ({(clamavDownloadProgress.speed_kbps / 1024).toFixed(1)} MB/s)
                        </span>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {clamavData ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-slate-50 border border-slate-200 p-4 rounded-2xl">
                  <div className="text-[10px] font-bold text-slate-400 uppercase">Daemon State</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        clamavData.status === 'ONLINE' ? 'bg-emerald-500' : 'bg-rose-500'
                      }`}
                    />
                    <span className="font-bold text-sm text-slate-900">{clamavData.status}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {clamavData.host}:{clamavData.port}
                  </div>
                </div>

                <div className="bg-slate-50 border border-slate-200 p-4 rounded-2xl">
                  <div className="text-[10px] font-bold text-slate-400 uppercase">Engine Version</div>
                  <div className="font-bold text-sm text-slate-900 mt-1 truncate">
                    {clamavData.engine_version}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">ClamAV Native</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 p-4 rounded-2xl flex flex-col justify-between">
                  <div>
                    <div className="text-[10px] font-bold text-slate-400 uppercase">Local Database Build</div>
                    <div className="font-bold text-sm text-slate-900 mt-1 truncate">
                      {clamavData.db_version}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 truncate">{clamavData.db_date}</div>
                  </div>
                  {clamavData.db_days_old_text && (
                    <div className="mt-2">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          (clamavData.db_days_old ?? 0) <= 2
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : (clamavData.db_days_old ?? 0) <= 7
                            ? 'bg-amber-50 text-amber-700 border border-amber-200'
                            : 'bg-rose-50 text-rose-700 border border-rose-200'
                        }`}
                      >
                        <span>🕒</span> {clamavData.db_days_old_text}
                      </span>
                    </div>
                  )}
                </div>

                <div className="bg-slate-50 border border-slate-200 p-4 rounded-2xl">
                  <div className="text-[10px] font-bold text-slate-400 uppercase">Active DB Files</div>
                  <div className="font-bold text-sm text-slate-900 mt-1">
                    {clamavData.definitions?.length || 0} Files
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Verified on disk</div>
                </div>
              </div>
            ) : (
              <div className="p-4 text-center text-slate-400 text-xs">ClamAV status unavailable</div>
            )}

            {/* Latest Online Definition Found Card */}
            {updateCheck.checked && (updateCheck.remote_version || updateCheck.latest_definition_summary) && (
              <div className="mb-6 p-5 bg-white rounded-3xl border border-slate-200 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3.5 border-b border-slate-100">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xl">🌐</span>
                    <div>
                      <h4 className="text-xs font-bold text-slate-800 tracking-wide uppercase">
                        Latest Online Definition Found
                      </h4>
                      <p className="text-[10px] text-slate-500">
                        Official Cisco Talos / ClamAV Global Mirror Network (<code className="text-slate-600 bg-slate-100 px-1 py-0.5 rounded font-mono">database.clamav.net</code>)
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {updateCheck.newer_available ? (
                      <span className="px-3 py-1 rounded-full text-xs font-bold bg-amber-50 text-amber-700 border border-amber-200 flex items-center gap-1.5">
                        <span>⚠️</span> Newer Definition Available Online
                      </span>
                    ) : (
                      <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1.5">
                        <span>✓</span> Up to Date with Online Mirror
                      </span>
                    )}
                    <button
                      onClick={() => triggerBackgroundUpdateCheck(true)}
                      disabled={updateCheck.loading}
                      className="px-3 py-1 bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 rounded-xl text-xs font-medium border border-slate-200 shadow-xs transition-colors flex items-center gap-1"
                      title="Re-check mirror"
                    >
                      <span>🔄</span> Re-check
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3.5">
                  <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-2xl">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">Latest Online Version</span>
                    <span className="text-sm font-mono font-bold text-indigo-600 mt-0.5 block">
                      daily.cvd v{updateCheck.remote_version || '28140'}
                    </span>
                    <span className="text-[10px] text-slate-500 mt-1 block">
                      Local: <span className="font-mono text-slate-700 font-semibold">v{updateCheck.local_version || clamavData?.db_version || 'unknown'}</span>
                    </span>
                  </div>

                  <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-2xl">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">Online Release Date</span>
                    <span className="text-xs font-semibold text-slate-800 mt-0.5 block truncate" title={updateCheck.remote_date}>
                      {updateCheck.remote_date || 'Today'}
                    </span>
                    <span className="text-[10px] text-slate-400 mt-1 block">Published by Talos</span>
                  </div>

                  <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-2xl">
                    <span className="text-[10px] text-slate-400 uppercase font-mono block">Signatures & Core</span>
                    <span className="text-xs font-mono font-bold text-slate-800 mt-0.5 block">
                      {updateCheck.remote_signatures ? updateCheck.remote_signatures.toLocaleString() + ' sigs' : '355,709 sigs'}
                    </span>
                    <span className="text-[10px] text-slate-500 mt-1 block">
                      Core: <span className="font-mono text-slate-700 font-medium">main.cvd v{updateCheck.remote_main_version || 63}</span>
                    </span>
                  </div>

                  <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-2xl flex flex-col justify-between">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase font-mono block">Check Timestamp</span>
                      <span className="text-xs font-mono text-slate-600 mt-0.5 block truncate">
                        {updateCheck.checked_at || 'Just now'}
                      </span>
                    </div>
                    {updateCheck.newer_available ? (
                      <button
                        onClick={handleUpdateClamav}
                        disabled={isUpdatingClamav || clamavDownloadProgress.is_downloading}
                        className="mt-2 w-full py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold shadow-sm transition-all"
                      >
                        Download Update Now →
                      </button>
                    ) : (
                      <span className="mt-2 text-[10px] text-emerald-600 font-semibold block">
                        ✓ Local signatures current
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Background Update Notification Banner if update is available and not downloading */}
            {updateCheck.newer_available && !clamavDownloadProgress.is_downloading && (
              <div className="mb-6 p-4 bg-gradient-to-r from-amber-50 to-orange-50 border border-amber-200 rounded-2xl flex flex-wrap items-center justify-between gap-3 shadow-sm">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">🔔</span>
                  <div>
                    <div className="text-xs font-bold text-amber-900 flex items-center gap-2">
                      Newer ClamAV Definition Files Available!
                      {updateCheck.remote_version && (
                        <span className="px-2 py-0.5 bg-amber-100 text-amber-800 text-[10px] font-mono rounded-full border border-amber-300">
                          Mirror v{updateCheck.remote_version} (Local: v{updateCheck.local_version || clamavData?.db_version || 'unknown'})
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-amber-700 mt-0.5">
                      {updateCheck.message || 'A newer daily signature database package was detected on the official ClamAV mirror.'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleUpdateClamav}
                    disabled={isUpdatingClamav}
                    className="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-sm transition-all flex items-center gap-1.5 whitespace-nowrap"
                  >
                    ⚡ Download Latest Database Now
                  </button>
                </div>
              </div>
            )}

            {updateCheck.error && !updateCheck.loading && (
              <div className="mb-6 px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-2xl flex items-center justify-between text-xs text-slate-600">
                <div className="flex items-center gap-2">
                  <span className="text-amber-500">ℹ️</span>
                  <span>Mirror check: {updateCheck.message || updateCheck.error}</span>
                </div>
                <button
                  onClick={() => triggerBackgroundUpdateCheck(true)}
                  className="text-[11px] font-semibold text-indigo-600 hover:text-indigo-800 underline"
                >
                  Retry check
                </button>
              </div>
            )}

            {/* Manual Upload */}
            <div className="p-5 bg-slate-50 border border-slate-200 rounded-2xl mb-6">
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
                📤 Manual Definition Upload
              </h3>
              <p className="text-xs text-slate-500 mb-3">
                Upload updated offline signature packages (<code className="font-mono text-slate-700">.cvd</code>, <code className="font-mono text-slate-700">.cld</code>, <code className="font-mono text-slate-700">.ndb</code>, <code className="font-mono text-slate-700">.yar</code>).
              </p>

              {uploadProgress.active && (
                <div className="mb-4 p-4 bg-white border border-slate-200 rounded-2xl text-slate-800 space-y-2 shadow-xs">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-800 flex items-center gap-2">
                      <svg className="animate-spin h-3.5 w-3.5 text-indigo-600" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                      </svg>
                      Uploading & Installing Definition File...
                    </span>
                    <span className="font-mono font-bold text-indigo-600">{uploadProgress.percent}%</span>
                  </div>
                  <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden border border-slate-200">
                    <div
                      className="bg-indigo-600 h-full rounded-full transition-all duration-200"
                      style={{ width: `${uploadProgress.percent}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] font-mono text-slate-500">
                    <span>{(uploadProgress.loaded / 1048576).toFixed(1)} MB / {(uploadProgress.total / 1048576).toFixed(1)} MB</span>
                    <span>Installing into /var/lib/clamav</span>
                  </div>
                </div>
              )}

              <form onSubmit={handleUploadDefinition} className="flex flex-wrap items-center gap-3">
                <input
                  type="file"
                  onChange={(e) => setUploadDefFile(e.target.files?.[0] || null)}
                  className="text-xs text-slate-600 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
                />
                <button
                  type="submit"
                  disabled={!uploadDefFile || isUploadingDef}
                  className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-40 text-white text-xs font-semibold rounded-lg shadow-sm"
                >
                  {isUploadingDef ? 'Installing...' : 'Install Definition File'}
                </button>
              </form>
            </div>

            {/* Community Threat Intelligence Signatures */}
            <div className="mb-6 p-5 bg-white border border-slate-200 rounded-2xl space-y-4">
              <div>
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                  <span>🛡️</span> Community Threat Intelligence Signatures
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  Enhance detection coverage with verified open-source signature databases for phishing, droppers, and 0-days.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* Sanesecurity */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="font-bold text-xs text-slate-900">Sanesecurity</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${
                        clamavData?.community_signatures?.sanesecurity?.installed
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {clamavData?.community_signatures?.sanesecurity?.installed ? 'Installed' : 'Available'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      High-accuracy scam, phishing bodies, and script droppers (foxhole, phish, scam).
                    </p>
                  </div>
                  <button
                    onClick={() => handleInstallCommunityClamav('sanesecurity')}
                    className="w-full py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-xl text-xs font-semibold transition-all cursor-pointer"
                  >
                    {clamavData?.community_signatures?.sanesecurity?.installed ? 'Sync Signatures' : 'Install Database'}
                  </button>
                </div>

                {/* URLhaus */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="font-bold text-xs text-slate-900">abuse.ch URLhaus</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${
                        clamavData?.community_signatures?.urlhaus?.installed
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {clamavData?.community_signatures?.urlhaus?.installed ? 'Installed' : 'Available'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      Real-time malicious payload download URLs and C2 distribution links formatted for ClamAV.
                    </p>
                  </div>
                  <button
                    onClick={() => handleInstallCommunityClamav('urlhaus')}
                    className="w-full py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-xl text-xs font-semibold transition-all cursor-pointer"
                  >
                    {clamavData?.community_signatures?.urlhaus?.installed ? 'Sync Signatures' : 'Install Database'}
                  </button>
                </div>

                {/* SecuriteInfo */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col justify-between space-y-3">
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="font-bold text-xs text-slate-900">SecuriteInfo</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${
                        clamavData?.community_signatures?.securiteinfo?.installed
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {clamavData?.community_signatures?.securiteinfo?.installed ? 'Installed' : 'Available'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      Daily 0-day malicious macros, PDF exploits, and JavaScript obfuscation heuristics.
                    </p>
                  </div>
                  <button
                    onClick={() => handleInstallCommunityClamav('securiteinfo')}
                    className="w-full py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-xl text-xs font-semibold transition-all cursor-pointer"
                  >
                    {clamavData?.community_signatures?.securiteinfo?.installed ? 'Sync Signatures' : 'Install Database'}
                  </button>
                </div>
              </div>
            </div>

            {/* Definitions Table */}
            {clamavData?.definitions && clamavData.definitions.length > 0 && (
              <div>
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-3">
                  Installed Definition Files
                </h3>
                <div className="overflow-x-auto border border-slate-200 rounded-2xl">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-100/70 border-b border-slate-200 text-slate-600 uppercase font-semibold">
                      <tr>
                        <th className="py-2.5 px-4">Filename</th>
                        <th className="py-2.5 px-4">Type</th>
                        <th className="py-2.5 px-4">Size</th>
                        <th className="py-2.5 px-4">Age</th>
                        <th className="py-2.5 px-4">Modified</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {clamavData.definitions.map((def: any) => (
                        <tr key={def.name} className="hover:bg-slate-50/80">
                          <td className="py-2 px-4 font-mono font-medium text-slate-900">{def.name}</td>
                          <td className="py-2 px-4">
                            <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-[10px] font-bold">
                              {def.type}
                            </span>
                          </td>
                          <td className="py-2 px-4 text-slate-600">
                            {(def.size_bytes / (1024 * 1024)).toFixed(2)} MB
                          </td>
                          <td className="py-2 px-4">
                            {def.days_old_text ? (
                              <span
                                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                  (def.days_old ?? 0) <= 2
                                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                                    : (def.days_old ?? 0) <= 7
                                    ? 'bg-amber-50 text-amber-700 border border-amber-200'
                                    : 'bg-slate-100 text-slate-700 border border-slate-200'
                                }`}
                              >
                                <span>🕒</span> {def.days_old_text}
                              </span>
                            ) : (
                              <span className="text-slate-400 text-[11px]">—</span>
                            )}
                          </td>
                          <td className="py-2 px-4 text-slate-500">{def.modified}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: YARA Rules */}
      {activeTab === 'yara' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>🔍</span> Custom YARA Heuristic Rules
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Author, edit, and validate pattern-matching rules executed during file triage.
              </p>
            </div>
            <button
              onClick={openNewYaraModal}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl shadow-sm flex items-center gap-1.5 transition-all"
            >
              <span>+</span> Create New YARA Rule
            </button>
          </div>

          {/* Curated Community YARA Repositories */}
          <div className="mb-6 p-5 bg-white border border-slate-200 rounded-2xl space-y-4">
            <div>
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                <span>📦</span> Curated Community YARA Repositories
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                Synchronize curated detection rule packs from YARA-Forge, yaralrules (CVE exploits), and yara-rules (threat actors & scripts).
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* YARA-Forge Core */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col justify-between space-y-3">
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-bold text-xs text-slate-900">YARA-Forge Core</span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 border border-indigo-200">
                      Curated Rules
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500">
                    High-confidence community rules compiled from YARA-Forge targeting commodity malware, stealers, and loaders.
                  </p>
                </div>
                <button
                  onClick={() => handleImportCommunityYara('yara-forge-core')}
                  className="w-full py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-xl text-xs font-semibold transition-all cursor-pointer"
                >
                  ⚡ Synchronize Pack
                </button>
              </div>

              {/* YaraRules Exploits */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col justify-between space-y-3">
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-bold text-xs text-slate-900">YaraRules & CVEs</span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-amber-50 text-amber-700 border border-amber-200">
                      Exploits
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500">
                    CVE detection rules for weaponized documents (Follina, MSHTML CVE-2021-40444, Equation Editor).
                  </p>
                </div>
                <button
                  onClick={() => handleImportCommunityYara('yaralrules-exploits')}
                  className="w-full py-1.5 bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 rounded-xl text-xs font-semibold transition-all cursor-pointer"
                >
                  ⚡ Synchronize Pack
                </button>
              </div>

              {/* Threat Actor & Scripts */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col justify-between space-y-3">
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-bold text-xs text-slate-900">Threat Actor Scripts</span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-purple-50 text-purple-700 border border-purple-200">
                      Scripts & Memory
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500">
                    In-memory AMSI/ETW patching, reverse shell sockets, and living-off-the-land LOLBin execution.
                  </p>
                </div>
                <button
                  onClick={() => handleImportCommunityYara('threat-actor-scripts')}
                  className="w-full py-1.5 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 rounded-xl text-xs font-semibold transition-all cursor-pointer"
                >
                  ⚡ Synchronize Pack
                </button>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            {yaraRules.map((rule) => (
              <div
                key={rule.id}
                className="p-4 border border-slate-200 bg-slate-50/60 rounded-2xl flex flex-wrap items-center justify-between gap-4 hover:border-slate-300 transition-all"
              >
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-xs text-slate-900">{rule.name}</span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        rule.severity === 'CRITICAL'
                          ? 'bg-rose-100 text-rose-800'
                          : rule.severity === 'HIGH'
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-indigo-100 text-indigo-800'
                      }`}
                    >
                      {rule.severity}
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 bg-slate-200/70 text-slate-700 rounded-full">
                      Format: {rule.target_format}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">{rule.description}</p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => openEditYaraModal(rule)}
                    className="px-3 py-1 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-medium rounded-lg transition-colors"
                  >
                    ✏️ Edit Rule
                  </button>
                  <button
                    onClick={() => handleToggleYaraRule(rule.id, rule.enabled)}
                    className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors ${
                      rule.enabled
                        ? 'bg-emerald-100 text-emerald-800 hover:bg-emerald-200'
                        : 'bg-slate-200 text-slate-600 hover:bg-slate-300'
                    }`}
                  >
                    {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                  </button>
                  <button
                    onClick={() => handleDeleteYaraRule(rule.id)}
                    className="px-2.5 py-1 text-rose-600 hover:bg-rose-50 rounded-lg text-xs font-semibold transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 6: Keyword & RegEx Watchlist */}
      {activeTab === 'warninglist' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>⚠️</span> Warning Keywords & Regular Expression Rules
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Flags sensitive phrases, confidential terms, or regex patterns detected in document bodies or metadata.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowRegexHelpModal(true)}
                className="px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-xs font-semibold rounded-xl flex items-center gap-1.5 transition-colors"
              >
                <span>💡</span> RegEx Help & Examples
              </button>
              <button
                onClick={openNewWarningModal}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl shadow-sm flex items-center gap-1.5 transition-all"
              >
                <span>+</span> Add Keyword / Regex Rule
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {warningRules.map((rule) => (
              <div
                key={rule.id}
                className="p-4 border border-slate-200 bg-slate-50/60 rounded-2xl flex flex-wrap items-center justify-between gap-4 hover:border-slate-300 transition-all"
              >
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2 flex-wrap">
                    {rule.name && (
                      <span className="font-bold text-sm text-slate-900">
                        {rule.name}
                      </span>
                    )}
                    <span className="font-mono text-xs bg-white px-2 py-0.5 border border-slate-300 rounded text-slate-800">
                      {rule.pattern}
                    </span>
                    {rule.is_regex && (
                      <span className="text-[10px] font-bold px-2 py-0.5 bg-indigo-100 text-indigo-800 rounded-full">
                        RegEx
                      </span>
                    )}
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        rule.severity === 'critical'
                          ? 'bg-rose-100 text-rose-800'
                          : rule.severity === 'high'
                          ? 'bg-amber-100 text-amber-800'
                          : rule.severity === 'medium'
                          ? 'bg-yellow-100 text-yellow-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {rule.severity.toUpperCase()}
                    </span>
                  </div>
                  {rule.description && (
                    <p className="text-xs text-slate-500">{rule.description}</p>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => openEditWarningModal(rule)}
                    className="px-3 py-1 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-medium rounded-lg transition-colors"
                  >
                    ✏️ Edit
                  </button>
                  <button
                    onClick={() => handleToggleWarningRule(rule.id)}
                    className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors ${
                      rule.enabled
                        ? 'bg-emerald-100 text-emerald-800 hover:bg-emerald-200'
                        : 'bg-slate-200 text-slate-600 hover:bg-slate-300'
                    }`}
                  >
                    {rule.enabled ? 'ACTIVE' : 'MUTED'}
                  </button>
                  <button
                    onClick={() => handleDeleteWarningRule(rule.id)}
                    className="px-2.5 py-1 text-rose-600 hover:bg-rose-50 rounded-lg text-xs font-semibold transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 6.5: Supported File Formats & Forensic Hex Patterns */}
      {activeTab === 'hex_patterns' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-100">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>🎯</span> Supported File Formats &amp; Forensic Hex Patterns
              </h2>
              <p className="text-xs text-slate-500 mt-1 max-w-2xl">
                Configure headline names, default extensions, and magic byte signatures for all supported file formats.
                Each format maintains its own dedicated list of structural patterns and forensic highlighting rules.
                System default formats cannot be deleted, but can be enabled or disabled.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={openNewFormatModal}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl shadow-sm flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <span>➕</span> Add New File Format
              </button>
            </div>
          </div>

          {/* Search bar */}
          <div className="flex items-center gap-3">
            <input
              type="text"
              placeholder="Search file formats, extensions, magic bytes, or patterns..."
              value={formatSearch}
              onChange={(e) => setFormatSearch(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
            />
          </div>

          {/* List of File Formats with Associated Patterns */}
          <div className="space-y-4">
            {fileFormats
              .filter((fmt) => {
                if (!formatSearch.trim()) return true;
                const q = formatSearch.toLowerCase();
                return (
                  fmt.name.toLowerCase().includes(q) ||
                  fmt.defaultExtension.toLowerCase().includes(q) ||
                  (fmt.magicBytes && fmt.magicBytes.toLowerCase().includes(q)) ||
                  (fmt.description && fmt.description.toLowerCase().includes(q)) ||
                  fmt.id.toLowerCase().includes(q)
                );
              })
              .map((fmt) => {
                const patMap = new Map<string, any>();
                for (const p of BUILTIN_FORMAT_PATTERNS.filter((p) => p.appliesToFormat === fmt.id)) {
                  patMap.set(p.id, { ...p, isBuiltin: true });
                }
                for (const p of customPatterns.filter((p) => p.appliesToFormat === fmt.id)) {
                  const existing = patMap.get(p.id);
                  if (existing) {
                    patMap.set(p.id, { ...existing, ...p, isBuiltin: true, isModified: true });
                  } else {
                    patMap.set(p.id, p);
                  }
                }
                const formatPatterns = Array.from(patMap.values());

                const allExts = fmt.extensions && fmt.extensions.length > 0 ? fmt.extensions : (fmt.defaultExtension ? [fmt.defaultExtension] : []);
                const allMagics = fmt.magicSignatures && fmt.magicSignatures.length > 0 ? fmt.magicSignatures : (fmt.magicBytes ? [fmt.magicBytes] : []);

                return (
                  <div
                    key={fmt.id}
                    className={`border rounded-2xl p-5 transition-all ${
                      fmt.enabled
                        ? 'border-slate-200 bg-white hover:border-slate-300 shadow-xs'
                        : 'border-slate-200 bg-slate-50/70 opacity-75'
                    }`}
                  >
                    {/* Format Header Card */}
                    <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="font-bold text-sm text-slate-900">{fmt.name}</h3>
                          <div className="flex items-center gap-1 flex-wrap">
                            {allExts.map((ext, extIdx) => (
                              <span key={extIdx} className="font-mono text-xs bg-slate-100 text-slate-700 px-2 py-0.5 rounded-md border border-slate-200 font-semibold">
                                {ext}
                              </span>
                            ))}
                          </div>
                          {allMagics.map((magic, magicIdx) => (
                            <span key={magicIdx} className="font-mono text-xs bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded-md border border-emerald-200 font-semibold">
                              Magic: {magic}
                            </span>
                          ))}
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider ${
                              fmt.isSystem
                                ? 'bg-slate-100 text-slate-600 border border-slate-200'
                                : 'bg-purple-50 text-purple-700 border border-purple-200'
                            }`}
                          >
                            {fmt.isSystem ? 'System Default' : 'Custom Format'}
                          </span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider ${
                              fmt.enabled
                                ? 'bg-emerald-100 text-emerald-800'
                                : 'bg-slate-200 text-slate-600'
                            }`}
                          >
                            {fmt.enabled ? 'Active' : 'Disabled'}
                          </span>
                        </div>
                        {fmt.description && (
                          <p className="text-xs text-slate-500 leading-relaxed max-w-3xl">
                            {fmt.description}
                          </p>
                        )}
                      </div>

                      {/* Format Actions */}
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => openNewPatternModal(fmt.id)}
                          className="px-3 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-lg border border-indigo-200 transition-colors cursor-pointer"
                        >
                          ➕ Add Pattern
                        </button>
                        <button
                          type="button"
                          onClick={() => openEditFormatModal(fmt)}
                          className="px-3 py-1 bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-semibold rounded-lg transition-colors cursor-pointer"
                        >
                          ✏️ Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => handleToggleFormat(fmt.id)}
                          className={`px-3 py-1 rounded-lg text-xs font-bold transition-colors cursor-pointer ${
                            fmt.enabled
                              ? 'bg-emerald-100 text-emerald-800 hover:bg-emerald-200'
                              : 'bg-slate-200 text-slate-600 hover:bg-slate-300'
                          }`}
                        >
                          {fmt.enabled ? 'ACTIVE' : 'MUTED'}
                        </button>
                        {fmt.isSystem ? (
                          <button
                            type="button"
                            disabled
                            className="px-2.5 py-1 text-slate-300 cursor-not-allowed text-xs font-semibold rounded-lg"
                            title="System default file formats cannot be deleted, only disabled."
                          >
                            Delete
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => handleDeleteFormat(fmt.id)}
                            className="px-2.5 py-1 text-rose-600 hover:bg-rose-50 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                          >
                            Delete
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Associated Patterns Table / List */}
                    <div className="mt-3">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                          Associated Patterns ({formatPatterns.length})
                        </span>
                      </div>

                      {formatPatterns.length === 0 ? (
                        <div className="p-4 rounded-xl bg-slate-50 border border-dashed border-slate-200 text-center text-xs text-slate-400">
                          No structural patterns defined for this format yet. Click &quot;➕ Add Pattern&quot; above to add byte signatures.
                        </div>
                      ) : (
                        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                          {formatPatterns.map((pat) => {
                            const isBuiltin = Boolean(pat.isBuiltin || pat.is_builtin || isBuiltinPattern(pat.id));
                            const isModified = Boolean(pat.isModified || pat.is_modified);
                            const stConf = STRUCTURE_COLORS[pat.structure_type as StructureType] || STRUCTURE_COLORS.header;

                            return (
                              <div
                                key={pat.id}
                                className="p-2.5 rounded-xl border border-slate-100 bg-slate-50/70 hover:bg-slate-50 flex flex-wrap items-center justify-between gap-3 text-xs transition-colors"
                              >
                                <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                                  <span
                                    className="w-3.5 h-3.5 rounded-full shrink-0 border border-black/10 shadow-2xs"
                                    style={{ backgroundColor: pat.color || '#10b981' }}
                                    title={`Color: ${pat.color}`}
                                  />
                                  <span className="font-bold text-slate-800">{pat.name}</span>
                                  <span
                                    className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                                    style={{
                                      backgroundColor: `${stConf.bg}20`,
                                      color: stConf.border,
                                      border: `1px solid ${stConf.border}40`,
                                    }}
                                  >
                                    {pat.structure_type}
                                  </span>

                                  {pat.type === 'struct_field' ? (
                                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
                                      STRUCT FIELD {pat.offset !== undefined ? `@0x${pat.offset.toString(16).toUpperCase()}` : ''} {pat.length ? `(${pat.length} B)` : ''}
                                    </span>
                                  ) : (
                                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-800">
                                      {pat.pattern}
                                      {pat.offset !== undefined ? ` @0x${pat.offset.toString(16).toUpperCase()}` : ''}
                                    </span>
                                  )}

                                  {/* Built-in / Edited / Custom Badges */}
                                  {isBuiltin ? (
                                    isModified ? (
                                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800 border border-amber-300 flex items-center gap-1">
                                        <span>✏️</span> Edited
                                      </span>
                                    ) : (
                                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-200/70 text-slate-600">
                                        System Default
                                      </span>
                                    )
                                  ) : (
                                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-100 text-purple-800 border border-purple-200">
                                      Custom
                                    </span>
                                  )}

                                  {pat.description && (
                                    <span className="text-slate-500 text-[11px] truncate max-w-sm hidden sm:inline" title={pat.description}>
                                      — {pat.description}
                                    </span>
                                  )}
                                </div>

                                <div className="flex items-center gap-1.5 shrink-0">
                                  {/* Edit button available for all patterns */}
                                  <button
                                    type="button"
                                    onClick={() => openEditPatternModal(pat)}
                                    className="px-2.5 py-0.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 rounded text-[11px] font-medium transition-colors cursor-pointer"
                                  >
                                    ✏️ Edit
                                  </button>

                                  {/* Reset button available for edited built-in patterns */}
                                  {isBuiltin && isModified && (
                                    <button
                                      type="button"
                                      onClick={() => handleResetPattern(pat.id)}
                                      className="px-2.5 py-0.5 bg-amber-50 hover:bg-amber-100 border border-amber-300 text-amber-800 rounded text-[11px] font-medium transition-colors cursor-pointer"
                                      title="Reset this pattern to its original system default"
                                    >
                                      ↺ Reset
                                    </button>
                                  )}

                                  {/* ON/OFF toggle available for all patterns */}
                                  <button
                                    type="button"
                                    onClick={() => handleTogglePattern(pat.id)}
                                    className={`px-2 py-0.5 rounded text-[10px] font-bold transition-colors cursor-pointer ${
                                      pat.enabled
                                        ? 'bg-emerald-100 text-emerald-800 hover:bg-emerald-200'
                                        : 'bg-slate-200 text-slate-600 hover:bg-slate-300'
                                    }`}
                                  >
                                    {pat.enabled ? 'ON' : 'OFF'}
                                  </button>

                                  {/* Delete only available for custom user patterns */}
                                  {!isBuiltin && (
                                    <button
                                      type="button"
                                      onClick={() => handleDeletePattern(pat.id)}
                                      className="px-2.5 py-0.5 text-rose-600 hover:bg-rose-50 rounded text-[11px] font-medium transition-colors cursor-pointer"
                                    >
                                      Delete
                                    </button>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* TAB 7: Upload Statistics */}
      {activeTab === 'statistics' && (
        !statisticsData ? (
          <div className="bg-white border border-slate-200 rounded-3xl p-12 text-center shadow-sm">
            <div className="inline-block animate-spin w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full mb-3" />
            <p className="text-sm font-semibold text-slate-800">Loading upload statistics & telemetry...</p>
            <button
              onClick={fetchStatistics}
              className="mt-4 px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors cursor-pointer"
            >
              🔄 Retry Loading Statistics
            </button>
          </div>
        ) : (
          (() => {
        const totalAnalyzed = statisticsData.total_files_analyzed || 0;
        const totalSanitized = statisticsData.total_files_sanitized || 0;
        const totalBytes = statisticsData.total_bytes_processed || 0;
        const avgSize = totalAnalyzed > 0 ? formatBytes(Math.round(totalBytes / totalAnalyzed)) : '0 B';
        const malwareCount = statisticsData.malware_detected_count || 0;
        const highRiskCount = statisticsData.high_risk_count || 0;
        const cleanCount = statisticsData.clean_count || 0;
        const threatsCount = malwareCount + highRiskCount;
        const threatRate = totalAnalyzed > 0 ? Math.round((threatsCount / totalAnalyzed) * 100) : 0;
        const cleanRate = totalAnalyzed > 0 ? Math.round((cleanCount / totalAnalyzed) * 100) : 100;

        const timeline = statisticsData.last_30_days || [];
        const maxDaily = Math.max(...timeline.map((t) => t.count), 5);
        const totalLast30Days = timeline.reduce((acc, t) => acc + t.count, 0);

        const sev = statisticsData.severity_distribution || {};
        const sevClean = sev.clean || cleanCount;
        const sevLow = sev.low || 0;
        const sevMedium = sev.medium || 0;
        const sevHigh = sev.high || highRiskCount;
        const sevCritical = sev.critical || 0;
        const sevMalware = sev.malware || malwareCount;

        return (
          <div className="space-y-6">
            {/* Top Key Metric Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-6 gap-3.5">
              <div className="bg-white border border-slate-200 p-4 rounded-3xl shadow-sm">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Total Scans</div>
                <div className="text-2xl font-extrabold text-slate-900 mt-1">{totalAnalyzed}</div>
                <div className="text-[11px] text-indigo-600 mt-0.5 font-medium">All-time uploads</div>
              </div>

              <div className="bg-white border border-slate-200 p-4 rounded-3xl shadow-sm">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Data Ingested</div>
                <div className="text-2xl font-extrabold text-slate-900 mt-1">{formatBytes(totalBytes)}</div>
                <div className="text-[11px] text-slate-500 mt-0.5 font-medium">Avg {avgSize} / file</div>
              </div>

              <div className="bg-white border border-slate-200 p-4 rounded-3xl shadow-sm">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Clean Documents</div>
                <div className="text-2xl font-extrabold text-emerald-600 mt-1">{cleanCount}</div>
                <div className="text-[11px] text-emerald-600 mt-0.5 font-medium">{cleanRate}% safe rate</div>
              </div>

              <div className="bg-white border border-slate-200 p-4 rounded-3xl shadow-sm">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Threats Detected</div>
                <div className="text-2xl font-extrabold text-rose-600 mt-1">{threatsCount}</div>
                <div className="text-[11px] text-rose-500 mt-0.5 font-medium">{threatRate}% threat ratio</div>
              </div>

              <div className="bg-white border border-slate-200 p-4 rounded-3xl shadow-sm">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Malware Blocked</div>
                <div className="text-2xl font-extrabold text-red-700 mt-1">{malwareCount}</div>
                <div className="text-[11px] text-red-600 mt-0.5 font-medium">ClamAV / PE hits</div>
              </div>

              <div className="bg-white border border-slate-200 p-4 rounded-3xl shadow-sm">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">CDR Sanitized</div>
                <div className="text-2xl font-extrabold text-indigo-600 mt-1">{totalSanitized}</div>
                <div className="text-[11px] text-indigo-600 mt-0.5 font-medium">Reconstructed clean</div>
              </div>
            </div>

            {/* 30-Day Daily Upload Activity Bar Chart */}
            <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-6">
                <div>
                  <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                    <span>📅</span> 30-Day Ingestion & Upload Timeline
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Daily file uploads processed across the multi-engine security pipeline over the past 30 days.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-slate-500">
                    30-Day Volume: <strong className="text-slate-900">{totalLast30Days}</strong> files
                  </span>
                  <span className="text-xs text-slate-500">
                    Daily Peak: <strong className="text-indigo-600">{maxDaily}</strong> files
                  </span>
                </div>
              </div>

              {/* Bar Chart Container */}
              <div className="h-44 flex items-end gap-1.5 sm:gap-2 pt-6 pb-2 px-2 border-b border-slate-200 bg-slate-50/50 rounded-2xl relative">
                {timeline.map((item, idx) => {
                  const barHeightPct = Math.max(8, Math.round((item.count / maxDaily) * 100));
                  const isToday = idx === timeline.length - 1;
                  return (
                    <div
                      key={item.date}
                      className="flex-1 flex flex-col items-center justify-end h-full group relative cursor-pointer"
                    >
                      {/* Hover Tooltip */}
                      <div className="absolute -top-12 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-20 bg-white text-slate-800 text-[11px] font-mono py-1 px-2.5 rounded-lg shadow-lg border border-slate-200 whitespace-nowrap -translate-x-1/2 left-1/2">
                        <div className="font-bold text-slate-900">{item.day}</div>
                        <div className="text-slate-500">{item.count} upload{item.count === 1 ? '' : 's'}</div>
                      </div>

                      {/* Bar Visual */}
                      <div
                        style={{ height: `${barHeightPct}%` }}
                        className={`w-full rounded-t-md transition-all duration-300 ${
                          item.count > 0
                            ? isToday
                              ? 'bg-gradient-to-t from-indigo-700 to-indigo-500 shadow-sm'
                              : 'bg-gradient-to-t from-indigo-500 to-blue-400 group-hover:from-indigo-600 group-hover:to-blue-500'
                            : 'bg-slate-200/80 group-hover:bg-slate-300'
                        }`}
                      />
                    </div>
                  );
                })}
              </div>

              {/* X-axis date labels */}
              <div className="flex justify-between items-center text-[10px] text-slate-400 font-mono mt-2 px-2">
                <span>{timeline[0]?.day || '30 days ago'}</span>
                <span>{timeline[Math.floor(timeline.length / 2)]?.day || '15 days ago'}</span>
                <span className="font-bold text-indigo-600">Today ({timeline[timeline.length - 1]?.day})</span>
              </div>
            </div>

            {/* Detailed Analytics Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Threat Severity Distribution */}
              <div className="bg-white border border-slate-200 p-6 rounded-3xl shadow-sm">
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <span>🎯</span> Threat Severity Distribution
                </h3>
                <div className="space-y-3.5">
                  {[
                    { label: 'Clean / Safe', count: sevClean, color: 'bg-emerald-500' },
                    { label: 'Low Risk', count: sevLow, color: 'bg-slate-400' },
                    { label: 'Medium Risk', count: sevMedium, color: 'bg-amber-400' },
                    { label: 'High Risk', count: sevHigh, color: 'bg-orange-500' },
                    { label: 'Critical Risk', count: sevCritical, color: 'bg-rose-500' },
                    { label: 'Malware / Exploit', count: sevMalware, color: 'bg-red-700' },
                  ].map((s) => {
                    const pct = totalAnalyzed > 0 ? Math.round((s.count / totalAnalyzed) * 100) : 0;
                    return (
                      <div key={s.label}>
                        <div className="flex justify-between text-xs mb-1 font-medium">
                          <span className="text-slate-700">{s.label}</span>
                          <span className="text-slate-500 font-mono">
                            <strong className="text-slate-900">{s.count}</strong> ({pct}%)
                          </span>
                        </div>
                        <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                          <div className={`${s.color} h-2 rounded-full transition-all`} style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Scans by File Format */}
              <div className="bg-white border border-slate-200 p-6 rounded-3xl shadow-sm">
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <span>📁</span> Scans by File Category
                </h3>
                <div className="space-y-3.5">
                  {Object.entries(statisticsData.categories_count || {}).map(([cat, count]) => {
                    const pct = totalAnalyzed > 0 ? Math.round((count / totalAnalyzed) * 100) : 0;
                    const getCategoryDetails = (c: string) => {
                      switch (c.toLowerCase()) {
                        case 'binary':
                        case 'executable':
                          return {
                            name: 'Compiled Binaries & Executables (binary)',
                            desc: 'Windows PE (.exe, .dll), Linux ELF, macOS Mach-O native machine code',
                          };
                        case 'svg_html':
                          return {
                            name: 'Web & Vector Graphics (svg_html)',
                            desc: 'HTML documents, SVG vector graphics, XML web payloads',
                          };
                        case 'script':
                          return {
                            name: 'Scripts & Interpreted Code (script)',
                            desc: 'JavaScript, Python, Shell, PowerShell, AppleScript, Batch',
                          };
                        case 'office':
                          return {
                            name: 'Office Productivity Documents (office)',
                            desc: 'Microsoft Word, Excel, PowerPoint, OpenDocument formats',
                          };
                        case 'pdf':
                          return {
                            name: 'PDF Documents (pdf)',
                            desc: 'Adobe Portable Document Format with stream inspection',
                          };
                        case 'image':
                          return {
                            name: 'Images & Visual Media (image)',
                            desc: 'PNG, JPEG, GIF, WebP, TIFF, AI-generated synthetic imagery',
                          };
                        case 'archive':
                          return {
                            name: 'Archives & Containers (archive)',
                            desc: 'ZIP, 7z, TAR, GZ, JAR archives, ISO disk images',
                          };
                        case 'email':
                          return {
                            name: 'Email Messages (email)',
                            desc: 'RFC-822 EML, Outlook MSG, email headers & attachments',
                          };
                        case 'extension':
                          return {
                            name: 'Browser Extensions (extension)',
                            desc: 'Chrome & Edge CRX packages, Firefox XPI extensions',
                          };
                        case 'domain':
                        case 'network':
                          return {
                            name: 'Network Infrastructure (domain/network)',
                            desc: 'Domain names, FQDNs, IPv4/IPv6 addresses',
                          };
                        default:
                          return {
                            name: `${c.charAt(0).toUpperCase() + c.slice(1)} (${c})`,
                            desc: 'General file format scans',
                          };
                      }
                    };
                    const details = getCategoryDetails(cat);
                    return (
                      <div key={cat} className="p-3 bg-slate-50/80 border border-slate-100 rounded-2xl">
                        <div className="flex justify-between items-start text-xs mb-1 font-medium">
                          <div>
                            <span className="font-semibold text-slate-800">{details.name}</span>
                            <p className="text-[11px] text-slate-500 font-normal mt-0.5">{details.desc}</p>
                          </div>
                          <span className="text-slate-500 font-mono shrink-0 ml-3 text-right">
                            <strong className="text-slate-900">{count}</strong> ({pct}%)
                          </span>
                        </div>
                        <div className="w-full bg-slate-200/70 rounded-full h-2 overflow-hidden mt-2">
                          <div className="bg-indigo-600 h-2 rounded-full transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Findings Breakdown & CDR Output */}
              <div className="space-y-6">
                {/* Findings */}
                <div className="bg-white border border-slate-200 p-6 rounded-3xl shadow-sm">
                  <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <span>🚨</span> Detected Security Indicators
                  </h3>
                  <div className="space-y-2">
                    {Object.entries(statisticsData.findings_breakdown || {}).map(([finding, count]) => (
                      <div key={finding} className="flex items-center justify-between text-xs">
                        <span className="capitalize font-medium text-slate-700">{finding}</span>
                        <span className="px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded-md font-bold font-mono">
                          {count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* CDR Formats */}
                <div className="bg-white border border-slate-200 p-6 rounded-3xl shadow-sm">
                  <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <span>🛡️</span> Content Disarm & Reconstruction (CDR)
                  </h3>
                  <div className="space-y-2">
                    {Object.entries(statisticsData.sanitization_formats || {}).map(([fmt, count]) => (
                      <div key={fmt} className="flex items-center justify-between text-xs">
                        <span className="capitalize font-medium text-slate-700">
                          {fmt === 'original' ? 'Disarmed Original Format' : `Converted to ${fmt.toUpperCase()}`}
                        </span>
                        <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded-md font-bold font-mono">
                          {count}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
      })()
      )
      )}

      {/* TAB 8: API Integration Guide */}
      {activeTab === 'history' && (
        <div className="space-y-4 animate-overlay-fade">
          {/* Header row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Upload History Log</h3>
              <p className="text-xs text-slate-500 mt-0.5">Complete record of all files analyzed. Toggle off to stop recording new entries.</p>
            </div>
            <div className="flex items-center gap-2">
              {/* Toggle */}
              <button
                onClick={async () => {
                  const newVal = !historyEnabled;
                  setHistoryEnabled(newVal);
                  await apiClient.toggleUploadHistory(token || '', newVal);
                }}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  historyEnabled ? 'bg-indigo-600' : 'bg-slate-300'
                }`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
                  historyEnabled ? 'translate-x-6' : 'translate-x-1'
                }`} />
              </button>
              <span className="text-xs font-medium text-slate-600">{historyEnabled ? 'Recording' : 'Paused'}</span>
              {/* Clear button */}
              <button
                onClick={async () => {
                  if (!window.confirm('Clear all upload history? This cannot be undone.')) return;
                  await apiClient.clearUploadHistory(token || '');
                  setUploadHistory([]);
                }}
                className="px-3 py-1.5 bg-white border border-rose-300 text-rose-700 text-xs font-semibold rounded-xl hover:bg-rose-50 transition-colors"
              >
                🗑 Clear All
              </button>
            </div>
          </div>

          {/* Search bar */}
          <input
            type="text"
            placeholder="Search by filename, hash, verdict..."
            value={historySearch}
            onChange={e => setHistorySearch(e.target.value)}
            className="w-full bg-white border border-slate-200 rounded-xl px-4 py-2 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
          />

          {/* Stats bar */}
          <div className="flex items-center gap-4 text-xs text-slate-500 font-medium">
            <span>{uploadHistory.length} total entries</span>
            {historySearch && <span>{uploadHistory.filter(h => JSON.stringify(h).toLowerCase().includes(historySearch.toLowerCase())).length} matching</span>}
          </div>

          {/* Table */}
          {historyLoading ? (
            <div className="text-center py-10 text-slate-400 text-sm">Loading history...</div>
          ) : uploadHistory.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-2xl border border-slate-200">
              <div className="text-4xl mb-3">📋</div>
              <p className="text-sm font-semibold text-slate-700">No upload history yet</p>
              <p className="text-xs text-slate-400 mt-1">Files analyzed while history is enabled will appear here.</p>
            </div>
          ) : (
            <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
              <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="bg-slate-50 sticky top-0 border-b border-slate-200">
                    <tr>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">Filename</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">Date / Time</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">Type</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">Verdict</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">VT Detection Ratio</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">ClamAV</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">Findings</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">MITRE</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">Size</th>
                      <th className="text-left px-4 py-3 font-semibold text-slate-500 uppercase tracking-wide text-[10px]">SHA-256</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {(() => {
                      const scanCountsByHash = new Map<string, any[]>();
                      for (const item of uploadHistory) {
                        const key = (item.sha256 && item.sha256.length > 10) ? item.sha256.toLowerCase() : (item.filename || '').toLowerCase();
                        if (!key) continue;
                        if (!scanCountsByHash.has(key)) scanCountsByHash.set(key, []);
                        scanCountsByHash.get(key)!.push(item);
                      }
                      scanCountsByHash.forEach((list) => {
                        list.sort((a, b) => new Date(b.uploaded_at || 0).getTime() - new Date(a.uploaded_at || 0).getTime());
                      });

                      return uploadHistory
                        .filter(h => !historySearch || JSON.stringify(h).toLowerCase().includes(historySearch.toLowerCase()))
                        .map((h, i) => {
                          const riskColor =
                            h.risk_level?.includes('MALICIOUS') ? 'text-red-700 bg-red-50 border-red-200' :
                            h.risk_level?.includes('HIGH') || h.risk_level?.includes('CRITICAL') ? 'text-orange-700 bg-orange-50 border-orange-200' :
                            h.risk_level?.includes('MEDIUM') ? 'text-amber-700 bg-amber-50 border-amber-200' :
                            h.risk_level?.includes('LOW') ? 'text-yellow-700 bg-yellow-50 border-yellow-200' :
                            'text-emerald-700 bg-emerald-50 border-emerald-200';
                          const dt = h.uploaded_at ? new Date(h.uploaded_at) : null;
                          const dateStr = dt ? dt.toLocaleDateString('en-GB') : '—';
                          const timeStr = dt ? dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : '';
                          const sizeStr = h.file_size > 1048576
                            ? `${(h.file_size / 1048576).toFixed(1)} MB`
                            : h.file_size > 1024
                            ? `${(h.file_size / 1024).toFixed(0)} KB`
                            : `${h.file_size} B`;

                          const fileKey = (h.sha256 && h.sha256.length > 10) ? h.sha256.toLowerCase() : (h.filename || '').toLowerCase();
                          const allScansForThisFile = (fileKey && scanCountsByHash.get(fileKey)) || [h];
                          const hasPreviousScans = allScansForThisFile.length > 1;

                          return (
                            <tr key={i} className="hover:bg-slate-50 transition-colors">
                              <td
                                className={`px-4 py-2.5 font-medium text-slate-800 max-w-[200px] ${hasPreviousScans ? 'cursor-pointer select-none' : ''}`}
                                onMouseEnter={(e) => {
                                  if (hasPreviousScans) {
                                    handleHistoryCellHover('previous_scans', { ...h, previous_scans: allScansForThisFile }, e);
                                  }
                                }}
                                onMouseLeave={handleHistoryCellLeave}
                                onClick={(e) => {
                                  if (hasPreviousScans) {
                                    handleHistoryCellClick('previous_scans', { ...h, previous_scans: allScansForThisFile }, e);
                                  }
                                }}
                                title={hasPreviousScans ? 'File scanned multiple times. Hover or click to inspect history.' : h.filename}
                              >
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="truncate max-w-[130px] block" title={h.filename}>{h.filename}</span>
                                  {hasPreviousScans && (
                                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-indigo-100 text-indigo-700 border border-indigo-200 shadow-2xs hover:bg-indigo-200 transition-colors">
                                      <span>🕒</span>
                                      <span>{allScansForThisFile.length}x</span>
                                    </span>
                                  )}
                                </div>
                              </td>
                            <td className="px-4 py-2.5 text-slate-500 whitespace-nowrap">
                              <span className="block">{dateStr}</span>
                              <span className="text-[10px] text-slate-400">{timeStr}</span>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="px-2 py-0.5 rounded-lg bg-slate-100 text-slate-700 font-mono text-[10px] font-semibold uppercase">{h.category}</span>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className={`px-2 py-0.5 rounded-lg border text-[10px] font-bold ${riskColor}`}>
                                {h.risk_level || '—'}
                              </span>
                            </td>

                            {/* VT Detection Ratio with Rich Hover Box */}
                            <td
                              className="px-4 py-2.5 font-mono text-xs cursor-pointer select-none"
                              onMouseEnter={(e) => handleHistoryCellHover('vt', h, e)}
                              onMouseLeave={handleHistoryCellLeave}
                              onClick={(e) => handleHistoryCellClick('vt', h, e)}
                              title="Click to lock popover open / Hover to inspect"
                            >
                              {h.vt_ratio || h.vt_score ? (
                                (() => {
                                  const ratioStr = h.vt_ratio || h.vt_score;
                                  const parts = String(ratioStr).split('/');
                                  const pos = parseInt(parts[0], 10);
                                  const isFlagged = !isNaN(pos) && pos > 0;
                                  return (
                                    <span
                                      className={`inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded-lg border transition-all ${
                                        isFlagged
                                          ? 'text-red-700 bg-red-50 border-red-200 font-bold hover:bg-red-100 hover:border-red-300'
                                          : 'text-emerald-700 bg-emerald-50 border-emerald-200 font-semibold hover:bg-emerald-100 hover:border-emerald-300'
                                      }`}
                                    >
                                      <span>{isFlagged ? '⚠️' : '✓'}</span>
                                      <span>{ratioStr}</span>
                                    </span>
                                  );
                                })()
                              ) : (
                                <span className="text-slate-400 font-mono text-[11px] hover:text-slate-600 transition-colors">
                                  —
                                </span>
                              )}
                            </td>

                            {/* ClamAV with Hover Box when not clean */}
                            <td
                              className={`px-4 py-2.5 ${h.clamav !== 'CLEAN' ? 'cursor-pointer select-none' : ''}`}
                              onMouseEnter={(e) => {
                                if (h.clamav !== 'CLEAN') {
                                  handleHistoryCellHover('clamav', h, e);
                                }
                              }}
                              onMouseLeave={handleHistoryCellLeave}
                              onClick={(e) => {
                                if (h.clamav !== 'CLEAN') {
                                  handleHistoryCellClick('clamav', h, e);
                                }
                              }}
                              title={h.clamav !== 'CLEAN' ? "Click to lock popover open / Hover to inspect" : undefined}
                            >
                              {h.clamav === 'CLEAN' ? (
                                <span className="px-2 py-0.5 rounded-lg text-emerald-700 bg-emerald-50 border border-emerald-200 text-[10px] font-bold">
                                  CLEAN
                                </span>
                              ) : h.clamav === 'DISABLED' ? (
                                <span
                                  className="px-2 py-0.5 rounded-lg text-slate-400 bg-slate-100 text-[10px] font-semibold hover:bg-slate-200 transition-colors"
                                  onMouseEnter={(e) => handleHistoryCellHover('clamav', h, e)}
                                  onMouseLeave={handleHistoryCellLeave}
                                  onClick={(e) => handleHistoryCellClick('clamav', h, e)}
                                >
                                  DISABLED
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded-lg text-red-700 bg-red-50 border border-red-300 text-[10px] font-bold inline-flex items-center gap-1 hover:bg-red-100 transition-colors">
                                  <span>🦠</span>
                                  <span className="max-w-[120px] truncate" title={h.clamav}>{h.clamav || 'INFECTED'}</span>
                                </span>
                              )}
                            </td>

                            {/* Findings with Hover Box when > 0 */}
                            <td
                              className={`px-4 py-2.5 text-center font-semibold ${h.findings_count > 0 ? 'cursor-pointer select-none' : ''}`}
                              onMouseEnter={(e) => {
                                if (h.findings_count > 0) {
                                  handleHistoryCellHover('findings', h, e);
                                }
                              }}
                              onMouseLeave={handleHistoryCellLeave}
                              onClick={(e) => {
                                if (h.findings_count > 0) {
                                  handleHistoryCellClick('findings', h, e);
                                }
                              }}
                              title={h.findings_count > 0 ? "Click to lock popover open / Hover to inspect" : undefined}
                            >
                              {h.findings_count > 0 ? (
                                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full font-bold text-xs bg-amber-100 text-amber-900 border border-amber-300 hover:bg-amber-200 transition-all shadow-xs">
                                  <span>⚠️</span>
                                  <span>{h.findings_count}</span>
                                </span>
                              ) : (
                                <span className="text-slate-400 font-medium text-xs">0</span>
                              )}
                            </td>

                            {/* MITRE with Hover Box when > 0 */}
                            <td
                              className={`px-4 py-2.5 text-center font-semibold ${h.mitre_count > 0 ? 'cursor-pointer select-none' : ''}`}
                              onMouseEnter={(e) => {
                                if (h.mitre_count > 0) {
                                  handleHistoryCellHover('mitre', h, e);
                                }
                              }}
                              onMouseLeave={handleHistoryCellLeave}
                              onClick={(e) => {
                                if (h.mitre_count > 0) {
                                  handleHistoryCellClick('mitre', h, e);
                                }
                              }}
                              title={h.mitre_count > 0 ? "Click to lock popover open / Hover to inspect" : undefined}
                            >
                              {h.mitre_count > 0 ? (
                                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full font-bold text-xs bg-purple-100 text-purple-900 border border-purple-300 hover:bg-purple-200 transition-all shadow-xs">
                                  <span>🎯</span>
                                  <span>{h.mitre_count}</span>
                                </span>
                              ) : (
                                <span className="text-slate-400 font-medium text-xs">0</span>
                              )}
                            </td>

                            <td className="px-4 py-2.5 text-slate-500 whitespace-nowrap">{sizeStr}</td>
                            <td className="px-4 py-2.5 font-mono text-[10px] text-slate-400 max-w-[100px] truncate" title={h.sha256}>{h.sha256 ? h.sha256.slice(0, 12) + '…' : '—'}</td>
                          </tr>
                        );
                      });
                    })()}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Floating Hover Popover Portal for History Inspection */}
          {activeHistoryTooltip && typeof document !== 'undefined' && createPortal(
            <div
              id="history-hover-popover"
              onMouseEnter={handleHistoryPopoverMouseEnter}
              onMouseLeave={handleHistoryPopoverMouseLeave}
              style={{
                position: 'fixed',
                left: activeHistoryTooltip.x,
                top: activeHistoryTooltip.y,
                transform: activeHistoryTooltip.showAbove ? 'translateY(-100%)' : 'none',
                zIndex: 9999,
              }}
              className={`${
                activeHistoryTooltip.type === 'findings' || activeHistoryTooltip.type === 'mitre' || activeHistoryTooltip.type === 'previous_scans'
                  ? 'w-[480px]'
                  : 'w-[380px]'
              } max-w-[94vw] bg-white text-slate-800 rounded-2xl p-4 shadow-2xl border border-slate-200 pointer-events-auto flex flex-col max-h-[460px] relative transition-opacity duration-150`}
            >
              {/* Invisible Hit Bridge to keep hover active between trigger cell and popover across the gap */}
              <div
                onMouseEnter={handleHistoryPopoverMouseEnter}
                style={{
                  position: 'absolute',
                  left: 0,
                  right: 0,
                  ...(activeHistoryTooltip.showAbove
                    ? { bottom: -22, height: 28 }
                    : { top: -22, height: 28 }),
                }}
                className="bg-transparent pointer-events-auto"
              />

              {/* 1. VirusTotal Tooltip */}
              {activeHistoryTooltip.type === 'vt' && (() => {
                const h = activeHistoryTooltip.entry;
                const vt = h.vt_details || {};
                const ratioStr = h.vt_ratio || h.vt_score || vt.ratio;
                const threatLabel = vt.suggested_threat_label;
                const threatCategory = vt.threat_category;
                const webLink = vt.web_link || (h.sha256 ? `https://www.virustotal.com/gui/file/${h.sha256}` : null);
                const parts = ratioStr ? String(ratioStr).split('/') : [];
                const positives = parts.length > 0 ? parseInt(parts[0], 10) : (vt.positives ?? 0);
                const totalEngines = parts.length > 1 ? parseInt(parts[1], 10) : (vt.total_engines ?? 0);
                const hasDetections = !isNaN(positives) && positives > 0;

                return (
                  <div className="flex flex-col gap-3">
                    <div className="flex items-center justify-between pb-2.5 border-b border-slate-100">
                      <div className="flex items-center gap-2">
                        <span className="text-base">🛡️</span>
                        <div>
                          <h4 className="text-xs font-bold text-slate-800 tracking-wide">VirusTotal Intelligence</h4>
                          <p className="text-[10px] text-slate-400 font-mono truncate max-w-[170px]" title={h.filename}>{h.filename}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="text-right">
                          <span className="text-[9px] text-slate-400 block uppercase font-mono">Detection Ratio</span>
                          <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                            hasDetections
                              ? 'text-rose-700 bg-rose-50 border border-rose-200'
                              : ratioStr
                              ? 'text-emerald-700 bg-emerald-50 border border-emerald-200'
                              : 'text-slate-500 bg-slate-100 border border-slate-200'
                          }`}>
                            {ratioStr || 'Not Scanned'}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(prev => prev ? { ...prev, isPinned: !prev.isPinned } : null)}
                          className={`p-1 rounded-lg text-xs transition-colors ${
                            activeHistoryTooltip.isPinned
                              ? 'bg-amber-50 text-amber-700 border border-amber-300'
                              : 'text-slate-400 hover:text-slate-700 hover:bg-slate-100'
                          }`}
                          title={activeHistoryTooltip.isPinned ? "Pinned (click to unpin)" : "Click to pin open"}
                        >
                          📌
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(null)}
                          className="w-5 h-5 flex items-center justify-center rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xs transition-colors"
                          title="Close (ESC)"
                        >
                          ✕
                        </button>
                      </div>
                    </div>

                    {/* Threat Label Card */}
                    {threatLabel ? (
                      <div className="p-3 rounded-xl bg-rose-50 border border-rose-200">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-rose-600 flex items-center gap-1">
                            <span>⚠️</span> Suggested Threat Label
                          </span>
                          {threatCategory && (
                            <span className="text-[9px] uppercase font-bold font-mono px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300">
                              {threatCategory}
                            </span>
                          )}
                        </div>
                        <div className="font-mono text-sm font-bold text-rose-900 break-all">
                          {threatLabel}
                        </div>
                      </div>
                    ) : hasDetections ? (
                      <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-800">
                        <span className="font-semibold">⚠️ Flagged by {positives} security engines.</span> Suspicious or malicious detection recorded on VirusTotal.
                      </div>
                    ) : ratioStr ? (
                      <div className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2">
                        <span className="text-base">✓</span>
                        <span>Clean. 0 threat detections reported across {totalEngines || 70}+ security vendors.</span>
                      </div>
                    ) : (
                      <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
                        VirusTotal API key was not configured during scan. You can still inspect this hash directly on VirusTotal below.
                      </div>
                    )}

                    {/* Vendor breakdown metrics */}
                    {(vt.total_engines > 0 || totalEngines > 0) && (
                      <div className="grid grid-cols-3 gap-2 py-1 text-center font-mono">
                        <div className="p-2 rounded-xl bg-slate-50 border border-slate-200">
                          <span className="text-[10px] text-slate-400 block">Malicious</span>
                          <span className={`text-sm font-bold ${positives > 0 ? 'text-rose-600' : 'text-slate-700'}`}>{positives}</span>
                        </div>
                        <div className="p-2 rounded-xl bg-slate-50 border border-slate-200">
                          <span className="text-[10px] text-slate-400 block">Suspicious</span>
                          <span className="text-sm font-bold text-amber-600">{vt.suspicious_count ?? 0}</span>
                        </div>
                        <div className="p-2 rounded-xl bg-slate-50 border border-slate-200">
                          <span className="text-[10px] text-slate-400 block">Total Engines</span>
                          <span className="text-sm font-bold text-slate-800">{totalEngines}</span>
                        </div>
                      </div>
                    )}

                    {vt.meaningful_name && (
                      <div className="text-[11px] text-slate-600 truncate">
                        <span className="text-slate-400 font-semibold">Identified As: </span>
                        <span className="font-mono text-slate-800">{vt.meaningful_name}</span>
                      </div>
                    )}
                    {Array.isArray(vt.tags) && vt.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {vt.tags.slice(0, 5).map((t: string, idx: number) => (
                          <span key={idx} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                            #{t}
                          </span>
                        ))}
                      </div>
                    )}

                    {webLink && (
                      <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs">
                        <span className="text-[10px] text-slate-400 font-mono truncate max-w-[150px]" title={h.sha256}>
                          {h.sha256 ? `${h.sha256.slice(0, 10)}…` : ''}
                        </span>
                        <a
                          href={webLink}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-indigo-600 hover:text-indigo-800 font-semibold inline-flex items-center gap-1 text-xs hover:underline"
                        >
                          <span>Open VirusTotal Report</span>
                          <span>↗</span>
                        </a>
                      </div>
                    )}

                    <div className="text-[10px] text-slate-400 pt-1.5 border-t border-slate-100 shrink-0 flex items-center justify-between">
                      <span>{activeHistoryTooltip.isPinned ? '📌 Locked open for scrolling' : '💡 Click cell to lock popover open'}</span>
                      <span className="font-mono text-slate-400">ESC to close</span>
                    </div>
                  </div>
                );
              })()}

              {/* 2. ClamAV Tooltip */}
              {activeHistoryTooltip.type === 'clamav' && (() => {
                const h = activeHistoryTooltip.entry;
                const cd = h.clamav_details || {};
                const status = String(cd.status || h.clamav).replace(/\0/g, '').trim();
                const rawThreat = cd.threat_name || (h.clamav !== 'CLEAN' ? h.clamav : null);
                const threatName = rawThreat ? String(rawThreat).replace(/\0/g, '').trim() : null;
                const isMalicious = status === 'MALICIOUS' || (threatName && !['DISABLED', 'ERROR', 'UNAVAILABLE', 'CLEAN'].includes(threatName));

                return (
                  <div className="flex flex-col gap-3">
                    <div className="flex items-center justify-between pb-2.5 border-b border-slate-100">
                      <div className="flex items-center gap-2">
                        <span className="text-base">🦠</span>
                        <div>
                          <h4 className="text-xs font-bold text-slate-800 tracking-wide">ClamAV Antivirus Inspection</h4>
                          <p className="text-[10px] text-slate-400 font-mono truncate max-w-[170px]" title={h.filename}>{h.filename}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] uppercase font-bold font-mono px-2 py-0.5 rounded border ${
                          isMalicious
                            ? 'bg-rose-50 text-rose-700 border-rose-200'
                            : status === 'DISABLED'
                            ? 'bg-slate-100 text-slate-500 border-slate-200'
                            : 'bg-amber-50 text-amber-700 border-amber-200'
                        }`}>
                          {status}
                        </span>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(prev => prev ? { ...prev, isPinned: !prev.isPinned } : null)}
                          className={`p-1 rounded-lg text-xs transition-colors ${
                            activeHistoryTooltip.isPinned
                              ? 'bg-amber-50 text-amber-700 border border-amber-300'
                              : 'text-slate-400 hover:text-slate-700 hover:bg-slate-100'
                          }`}
                          title={activeHistoryTooltip.isPinned ? "Pinned (click to unpin)" : "Click to pin open"}
                        >
                          📌
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(null)}
                          className="w-5 h-5 flex items-center justify-center rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xs transition-colors"
                          title="Close (ESC)"
                        >
                          ✕
                        </button>
                      </div>
                    </div>

                    {threatName && (
                      <div className="p-3 rounded-xl bg-rose-50 border border-rose-200">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-rose-600 flex items-center gap-1 mb-1">
                          <span>⚠️</span> Detected Threat Signature
                        </span>
                        <div className="font-mono text-sm font-bold text-rose-900 break-all">
                          {threatName}
                        </div>
                        <p className="text-[11px] text-rose-800/90 mt-2 leading-relaxed">
                          Flagged by ClamAV real-time daemon. File download and sanitization are locked by platform security policy.
                        </p>
                      </div>
                    )}

                    {status === 'DISABLED' && (
                      <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
                        ClamAV scanner was disabled in configuration when this file was analyzed.
                      </div>
                    )}
                    {(status === 'ERROR' || status === 'UNAVAILABLE') && (
                      <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-800">
                        <p className="font-bold">Antivirus Daemon Notice:</p>
                        <p className="mt-1 font-mono text-[11px]">{cd.error_message || 'ClamAV daemon at clamav:3310 did not respond or stream timed out.'}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-100">
                      <div>
                        <span className="text-slate-400 block text-[10px]">Engine Version:</span>
                        <span className="font-mono text-slate-800 font-semibold">{cd.engine_version || 'ClamAV'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Signature DB:</span>
                        <span className="font-mono text-slate-800 truncate block" title={cd.signature_db}>{cd.signature_db || 'Active'}</span>
                      </div>
                    </div>
                    {cd.scan_timestamp && (
                      <div className="text-[10px] text-slate-400 flex items-center justify-between">
                        <span>Scanned At:</span>
                        <span className="font-mono text-slate-600">{new Date(cd.scan_timestamp).toLocaleString('en-GB')}</span>
                      </div>
                    )}

                    <div className="text-[10px] text-slate-400 pt-1.5 border-t border-slate-100 shrink-0 flex items-center justify-between">
                      <span>{activeHistoryTooltip.isPinned ? '📌 Locked open for scrolling' : '💡 Click cell to lock popover open'}</span>
                      <span className="font-mono text-slate-400">ESC to close</span>
                    </div>
                  </div>
                );
              })()}

              {/* 3. Findings Tooltip */}
              {activeHistoryTooltip.type === 'findings' && (() => {
                const h = activeHistoryTooltip.entry;
                const list = Array.isArray(h.findings) ? h.findings : [];

                return (
                  <div className="flex flex-col gap-3 max-h-[440px]">
                    <div className="flex items-center justify-between pb-2.5 border-b border-slate-100 shrink-0">
                      <div className="flex items-center gap-2">
                        <span className="text-base">⚠️</span>
                        <div>
                          <h4 className="text-xs font-bold text-slate-800 tracking-wide">Security Findings</h4>
                          <p className="text-[10px] text-slate-400 font-mono truncate max-w-[190px]" title={h.filename}>{h.filename}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-50 text-amber-700 border border-amber-200">
                          {h.findings_count} {h.findings_count === 1 ? 'finding' : 'findings'}
                        </span>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(prev => prev ? { ...prev, isPinned: !prev.isPinned } : null)}
                          className={`p-1 rounded-lg text-xs transition-colors ${
                            activeHistoryTooltip.isPinned
                              ? 'bg-amber-50 text-amber-700 border border-amber-300'
                              : 'text-slate-400 hover:text-slate-700 hover:bg-slate-100'
                          }`}
                          title={activeHistoryTooltip.isPinned ? "Pinned (click to unpin)" : "Click to pin open"}
                        >
                          📌
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(null)}
                          className="w-5 h-5 flex items-center justify-center rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xs transition-colors"
                          title="Close (ESC)"
                        >
                          ✕
                        </button>
                      </div>
                    </div>

                    <div
                      className="overflow-y-auto max-h-[300px] pr-2 space-y-2 select-text"
                      style={{
                        scrollbarWidth: 'thin',
                        scrollbarColor: '#cbd5e1 #f8fafc',
                      }}
                    >
                      {list.length > 0 ? (
                        list.map((f: any, idx: number) => {
                          const sev = (f.severity || 'medium').toLowerCase();
                          const sevBadge =
                            sev === 'critical' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                            sev === 'high' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                            sev === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                            sev === 'low' ? 'bg-yellow-50 text-yellow-700 border-yellow-200' :
                            'bg-blue-50 text-blue-700 border-blue-200';

                          return (
                            <div key={idx} className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition-colors">
                              <div className="flex items-center justify-between gap-2 mb-1">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className={`text-[9px] uppercase font-bold font-mono px-1.5 py-0.5 rounded border ${sevBadge}`}>
                                    {sev}
                                  </span>
                                  {f.category && (
                                    <span className="text-[9px] uppercase font-mono px-1.5 py-0.5 rounded bg-white text-slate-500 border border-slate-200">
                                      {f.category}
                                    </span>
                                  )}
                                </div>
                              </div>
                              <div className="font-semibold text-xs text-slate-900 leading-snug">
                                {f.title}
                              </div>
                              {f.description && (
                                <p className="text-[11px] text-slate-600 mt-1 line-clamp-2 leading-relaxed">
                                  {f.description}
                                </p>
                              )}
                            </div>
                          );
                        })
                      ) : (
                        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
                          <p className="font-bold text-slate-900 mb-1">Findings Summary</p>
                          <p className="text-slate-600 text-[11px] leading-relaxed">
                            This file registered <strong className="text-amber-700">{h.findings_count} findings</strong> during static security analysis.
                            Risk: <strong className="text-slate-900">{h.risk_level}</strong>.
                            Verdict: <strong className="text-slate-800">{h.verdict || 'Active indicators present'}</strong>.
                          </p>
                        </div>
                      )}
                    </div>

                    <div className="text-[10px] text-slate-400 pt-1.5 border-t border-slate-100 shrink-0 flex items-center justify-between">
                      <span>{activeHistoryTooltip.isPinned ? '📌 Locked open for scrolling' : '💡 Click cell to lock popover open'}</span>
                      <span>Total Findings: {h.findings_count}</span>
                    </div>
                  </div>
                );
              })()}

              {/* 4. MITRE Tooltip */}
              {activeHistoryTooltip.type === 'mitre' && (() => {
                const h = activeHistoryTooltip.entry;
                const list = Array.isArray(h.mitre_details) ? h.mitre_details : [];

                return (
                  <div className="flex flex-col gap-3 max-h-[440px]">
                    <div className="flex items-center justify-between pb-2.5 border-b border-slate-100 shrink-0">
                      <div className="flex items-center gap-2">
                        <span className="text-base">🎯</span>
                        <div>
                          <h4 className="text-xs font-bold text-slate-800 tracking-wide">MITRE ATT&CK Techniques</h4>
                          <p className="text-[10px] text-slate-400 font-mono truncate max-w-[190px]" title={h.filename}>{h.filename}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-purple-50 text-purple-700 border border-purple-200">
                          {h.mitre_count} mapped
                        </span>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(prev => prev ? { ...prev, isPinned: !prev.isPinned } : null)}
                          className={`p-1 rounded-lg text-xs transition-colors ${
                            activeHistoryTooltip.isPinned
                              ? 'bg-amber-50 text-amber-700 border border-amber-300'
                              : 'text-slate-400 hover:text-slate-700 hover:bg-slate-100'
                          }`}
                          title={activeHistoryTooltip.isPinned ? "Pinned (click to unpin)" : "Click to pin open"}
                        >
                          📌
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(null)}
                          className="w-5 h-5 flex items-center justify-center rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xs transition-colors"
                          title="Close (ESC)"
                        >
                          ✕
                        </button>
                      </div>
                    </div>

                    <div
                      className="overflow-y-auto max-h-[300px] pr-2 space-y-2 select-text"
                      style={{
                        scrollbarWidth: 'thin',
                        scrollbarColor: '#cbd5e1 #f8fafc',
                      }}
                    >
                      {list.length > 0 ? (
                        list.map((m: any, idx: number) => {
                          const techUrl = m.url || (m.id ? `https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/` : null);

                          return (
                            <div key={idx} className="p-2.5 rounded-xl bg-slate-50 border border-slate-200 hover:border-purple-300 transition-colors">
                              <div className="flex items-center justify-between gap-2 mb-1">
                                <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200">
                                  {m.id}
                                </span>
                                {m.tactic && (
                                  <span className="text-[9px] uppercase font-bold font-mono px-1.5 py-0.5 rounded bg-white text-slate-500 border border-slate-200">
                                    {m.tactic}
                                  </span>
                                )}
                              </div>
                              <div className="font-bold text-xs text-slate-900 leading-snug">
                                {m.name}
                              </div>
                              {techUrl && (
                                <div className="mt-2 pt-1.5 border-t border-slate-200 flex justify-end">
                                  <a
                                    href={techUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-purple-600 hover:text-purple-800 font-medium inline-flex items-center gap-1 text-[11px] hover:underline"
                                  >
                                    <span>Explore Technique on attack.mitre.org</span>
                                    <span>↗</span>
                                  </a>
                                </div>
                              )}
                            </div>
                          );
                        })
                      ) : (
                        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
                          <p className="font-bold text-slate-900 mb-1">ATT&CK Mapping Summary</p>
                          <p className="text-slate-600 text-[11px] leading-relaxed">
                            This file was mapped to <strong className="text-purple-700">{h.mitre_count} MITRE ATT&CK techniques</strong> based on static findings, script behaviors, and format indicators.
                          </p>
                        </div>
                      )}
                    </div>

                    <div className="text-[10px] text-slate-400 pt-1.5 border-t border-slate-100 shrink-0 flex items-center justify-between">
                      <span>{activeHistoryTooltip.isPinned ? '📌 Locked open for scrolling' : '💡 Click cell to lock popover open'}</span>
                      <span>Total Techniques: {h.mitre_count}</span>
                    </div>
                  </div>
                );
              })()}

              {/* 5. Previous Scans History Tooltip */}
              {activeHistoryTooltip.type === 'previous_scans' && (() => {
                const h = activeHistoryTooltip.entry;
                const scans = (activeHistoryTooltip.previousScans && activeHistoryTooltip.previousScans.length > 0)
                  ? activeHistoryTooltip.previousScans
                  : (h.previous_scans || [h]);

                return (
                  <div className="flex flex-col gap-3 max-h-[440px]">
                    <div className="flex items-center justify-between pb-2.5 border-b border-slate-100 shrink-0">
                      <div className="flex items-center gap-2">
                        <span className="text-base">🕒</span>
                        <div>
                          <h4 className="text-xs font-bold text-slate-800 tracking-wide flex items-center gap-1.5">
                            <span>Scan History</span>
                            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-indigo-100 text-indigo-700">
                              {scans.length} scans recorded
                            </span>
                          </h4>
                          <p className="text-[10px] text-slate-400 font-mono truncate max-w-[200px]" title={h.filename}>
                            {h.filename}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(prev => prev ? { ...prev, isPinned: !prev.isPinned } : null)}
                          className={`p-1 rounded-lg text-xs transition-colors ${
                            activeHistoryTooltip.isPinned
                              ? 'bg-amber-50 text-amber-700 border border-amber-300'
                              : 'text-slate-400 hover:text-slate-700 hover:bg-slate-100'
                          }`}
                          title={activeHistoryTooltip.isPinned ? "Pinned (click to unpin)" : "Click to pin open"}
                        >
                          📌
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveHistoryTooltip(null)}
                          className="w-5 h-5 flex items-center justify-center rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xs transition-colors"
                          title="Close (ESC)"
                        >
                          ✕
                        </button>
                      </div>
                    </div>

                    <div
                      className="space-y-2 overflow-y-auto pr-1 flex-1"
                      style={{
                        scrollbarWidth: 'thin',
                        scrollbarColor: '#cbd5e1 #f8fafc',
                      }}
                    >
                      {scans.map((s: any, idx: number) => {
                        const sDate = s.uploaded_at ? new Date(s.uploaded_at) : null;
                        const dateStr = sDate ? sDate.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
                        const timeStr = sDate ? sDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
                        const riskColor =
                          s.risk_level?.includes('MALICIOUS') ? 'text-red-700 bg-red-50 border-red-200' :
                          s.risk_level?.includes('HIGH') || s.risk_level?.includes('CRITICAL') ? 'text-orange-700 bg-orange-50 border-orange-200' :
                          s.risk_level?.includes('MEDIUM') ? 'text-amber-700 bg-amber-50 border-amber-200' :
                          s.risk_level?.includes('LOW') ? 'text-yellow-700 bg-yellow-50 border-yellow-200' :
                          'text-emerald-700 bg-emerald-50 border-emerald-200';

                        const isCurrentScan = Boolean((s.job_id || s.id) && (s.job_id || s.id) === (h.job_id || h.id));

                        return (
                          <div
                            key={s.job_id || s.id || idx}
                            className={`p-2.5 rounded-xl border transition-all ${
                              isCurrentScan ? 'bg-indigo-50/50 border-indigo-200 ring-1 ring-indigo-300' : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2 mb-1.5">
                              <div className="flex items-center gap-1.5">
                                <span className="text-xs font-bold text-slate-800">{dateStr}</span>
                                <span className="text-[10px] font-mono text-slate-500">{timeStr}</span>
                                {isCurrentScan && (
                                  <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-indigo-100 text-indigo-700">
                                    Current
                                  </span>
                                )}
                              </div>
                              <span className={`px-2 py-0.5 rounded-md border text-[10px] font-bold ${riskColor}`}>
                                {s.risk_level || 'CLEAN'}
                              </span>
                            </div>

                            <div className="grid grid-cols-3 gap-2 text-center font-mono text-[10px] mt-1 pt-1.5 border-t border-slate-100">
                              <div className="bg-white p-1 rounded border border-slate-200">
                                <span className="text-slate-400 block text-[9px]">VT Score</span>
                                <span className="font-bold text-slate-800">{s.vt_ratio || s.vt_score || '—'}</span>
                              </div>
                              <div className="bg-white p-1 rounded border border-slate-200">
                                <span className="text-slate-400 block text-[9px]">ClamAV</span>
                                <span className="font-bold text-slate-800">{s.clamav || '—'}</span>
                              </div>
                              <div className="bg-white p-1 rounded border border-slate-200">
                                <span className="text-slate-400 block text-[9px]">Findings</span>
                                <span className="font-bold text-slate-800">{s.findings_count ?? (s.findings?.length || 0)}</span>
                              </div>
                            </div>

                            {s.sha256 && (
                              <div className="mt-1 text-[9px] font-mono text-slate-400 truncate" title={s.sha256}>
                                SHA-256: {s.sha256}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    <div className="text-[10px] text-slate-400 pt-1.5 border-t border-slate-100 shrink-0 flex items-center justify-between">
                      <span>{activeHistoryTooltip.isPinned ? '📌 Locked open for scrolling' : '💡 Click filename to lock popover open'}</span>
                      <span className="font-mono text-slate-400">ESC to close</span>
                    </div>
                  </div>
                );
              })()}
            </div>,
            document.body
          )}
        </div>
      )}

      {/* TAB 8.5: Application Audit & System Debug Logs */}
      {activeTab === 'audit_logs' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>📜</span> Application Audit &amp; System Debug Logs
              </h2>
              <p className="text-xs text-slate-500 mt-1 max-w-2xl">
                Continuous real-time audit trail and diagnostic logging for security auditing and debugging.
                Captures file ingestion, static analyzers, threat intelligence queries, ClamAV/YARA execution, and system exceptions.
              </p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {/* Log Level Selector */}
              <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-xl text-xs">
                <span className="text-slate-500 font-medium">Log Level:</span>
                <select
                  value={auditLogLevel}
                  onChange={(e) => handleSetLogLevel(e.target.value)}
                  className="bg-transparent font-bold text-slate-800 focus:outline-none cursor-pointer"
                >
                  <option value="DEBUG">DEBUG (All logs)</option>
                  <option value="INFO">INFO (Normal)</option>
                  <option value="WARNING">WARNING (Issues only)</option>
                  <option value="ERROR">ERROR (Errors only)</option>
                </select>
              </div>

              {/* Auto-refresh Toggle */}
              <button
                type="button"
                onClick={() => setAuditAutoRefresh((prev) => !prev)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all flex items-center gap-1.5 cursor-pointer ${
                  auditAutoRefresh
                    ? 'bg-emerald-50 border-emerald-300 text-emerald-800 shadow-2xs'
                    : 'bg-slate-50 hover:bg-slate-100 text-slate-600 border-slate-200'
                }`}
                title="Automatically refresh log stream every 3 seconds"
              >
                <span className={`w-2 h-2 rounded-full ${auditAutoRefresh ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
                <span>{auditAutoRefresh ? 'Live Streaming' : 'Auto-refresh'}</span>
              </button>

              {/* Manual Refresh */}
              <button
                type="button"
                onClick={() => fetchAuditLogs()}
                disabled={isLoadingAuditLogs}
                className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl border border-slate-200 transition-colors flex items-center gap-1 cursor-pointer disabled:opacity-50"
              >
                <span className={isLoadingAuditLogs ? 'animate-spin' : ''}>🔄</span>
                <span>Refresh</span>
              </button>

              {/* Export Text Log */}
              <a
                href={apiClient.exportAuditLogsUrl(token, 'text')}
                download
                className="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors flex items-center gap-1"
                title="Download raw .log plain text file"
              >
                <span>💾</span>
                <span>Download .log</span>
              </a>

              {/* Export JSON */}
              <a
                href={apiClient.exportAuditLogsUrl(token, 'json')}
                download
                className="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors flex items-center gap-1"
                title="Download JSON structured log file"
              >
                <span>📄</span>
                <span>JSON</span>
              </a>

              {/* Clear Logs */}
              <button
                type="button"
                onClick={handleClearAuditLogs}
                className="px-3 py-1.5 bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-semibold rounded-xl border border-rose-200 transition-colors flex items-center gap-1 cursor-pointer"
                title="Clear current log buffer"
              >
                <span>🗑️</span>
                <span>Clear</span>
              </button>
            </div>
          </div>

          {/* Search and Severity Filter Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1.5 flex-wrap">
              {[
                { id: 'ALL', label: 'All Severities', count: auditCounts.TOTAL, color: 'slate' },
                { id: 'ERROR', label: 'Errors', count: auditCounts.ERROR + auditCounts.CRITICAL, color: 'rose' },
                { id: 'WARNING', label: 'Warnings', count: auditCounts.WARNING, color: 'amber' },
                { id: 'INFO', label: 'Info', count: auditCounts.INFO, color: 'blue' },
                { id: 'DEBUG', label: 'Debug', count: auditCounts.DEBUG, color: 'purple' },
              ].map((lvl) => {
                const isActive = auditFilterLevel === lvl.id;
                return (
                  <button
                    key={lvl.id}
                    type="button"
                    onClick={() => {
                      setAuditFilterLevel(lvl.id);
                      fetchAuditLogs(lvl.id);
                    }}
                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all flex items-center gap-1.5 cursor-pointer ${
                      isActive
                        ? 'bg-slate-900 text-white shadow-sm'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    <span>{lvl.label}</span>
                    <span
                      className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-full ${
                        isActive ? 'bg-white/20 text-white' : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {lvl.count}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Search Input */}
            <div className="relative min-w-[260px]">
              <input
                type="text"
                placeholder="Search message, module, exception, or job ID..."
                value={auditSearch}
                onChange={(e) => {
                  setAuditSearch(e.target.value);
                  fetchAuditLogs(undefined, e.target.value);
                }}
                className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
              />
              <span className="absolute left-2.5 top-2 text-slate-400 text-xs">🔍</span>
              {auditSearch && (
                <button
                  type="button"
                  onClick={() => {
                    setAuditSearch('');
                    fetchAuditLogs(undefined, '');
                  }}
                  className="absolute right-2.5 top-1.5 text-slate-400 hover:text-slate-600 text-xs cursor-pointer"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Logs Table / Console View */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden shadow-2xs">
            <div className="bg-slate-50 text-slate-800 px-4 py-2.5 text-xs font-mono font-bold flex items-center justify-between border-b border-slate-200">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                <span>FileSanitizer Engine Log Stream</span>
                <span className="text-slate-500 text-[11px] font-normal">
                  ({auditLogs.length} records displayed)
                </span>
              </div>
              <div className="flex items-center gap-3 text-[11px] text-slate-500 font-sans">
                <span>Active Level: <strong className="text-slate-900 uppercase font-mono">{auditLogLevel}</strong></span>
              </div>
            </div>

            <div
              className="max-h-[580px] overflow-y-auto divide-y divide-slate-100 bg-white"
              style={{ scrollbarWidth: 'thin', scrollbarColor: '#cbd5e1 #f8fafc' }}
            >
              {auditLogs.length === 0 ? (
                <div className="p-12 text-center text-slate-500">
                  <span className="text-2xl block mb-2">📜</span>
                  <p className="text-xs font-semibold text-slate-700">No audit log records match the current filter.</p>
                  <p className="text-[11px] text-slate-400 mt-1">Logs are generated in real-time as files are uploaded, analyzed, or sanitized.</p>
                </div>
              ) : (
                auditLogs.map((log) => {
                  const isError = log.level === 'ERROR' || log.level === 'CRITICAL';
                  const isWarn = log.level === 'WARNING';
                  const isDebug = log.level === 'DEBUG';

                  const badgeClass = isError
                    ? 'bg-rose-100 text-rose-800 border-rose-200'
                    : isWarn
                    ? 'bg-amber-100 text-amber-800 border-amber-200'
                    : isDebug
                    ? 'bg-purple-100 text-purple-800 border-purple-200'
                    : 'bg-blue-100 text-blue-800 border-blue-200';

                  const isExpanded = expandedLogId === log.id;

                  return (
                    <div
                      key={log.id}
                      className={`p-3 font-mono text-xs transition-colors hover:bg-slate-50/80 ${
                        isError ? 'bg-rose-50/20' : isWarn ? 'bg-amber-50/20' : ''
                      }`}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap min-w-0">
                          {/* Timestamp */}
                          <span className="text-slate-400 text-[11px] shrink-0">
                            {log.time_str || log.timestamp}
                          </span>

                          {/* Level Badge */}
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border shrink-0 ${badgeClass}`}
                          >
                            {log.level}
                          </span>

                          {/* Source Module:Line */}
                          <span className="text-slate-500 text-[11px] bg-slate-100 px-1.5 py-0.5 rounded shrink-0">
                            {log.module || log.logger}:{log.line}
                          </span>
                        </div>

                        {/* Expand Traceback button if exception present */}
                        {log.exception && (
                          <button
                            type="button"
                            onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                            className="px-2 py-0.5 rounded bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-[10px] font-bold font-sans transition-colors cursor-pointer shrink-0"
                          >
                            {isExpanded ? 'Hide Traceback ▲' : 'View Traceback ▼'}
                          </button>
                        )}
                      </div>

                      {/* Log Message */}
                      <div className="mt-1 text-slate-800 text-xs font-mono break-all whitespace-pre-wrap leading-relaxed">
                        {log.message}
                      </div>

                      {/* Stack Trace / Exception Details */}
                      {log.exception && isExpanded && (
                        <div className="mt-2.5 p-3 rounded-xl bg-rose-50 text-rose-900 text-[11px] font-mono overflow-x-auto whitespace-pre leading-relaxed border border-rose-200">
                          {log.exception}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 9: API Integration Guide */}
      {activeTab === 'api_docs' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          <div>
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <span>⚡</span> REST API Integration & Automation Guide
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              FileSanitizer provides a fast, stateless REST API to integrate file inspection and CDR reconstruction into automated email gateways, CI/CD pipelines, and internal portals.
            </p>
          </div>

          {/* Endpoints Reference Table */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden">
            <div className="bg-slate-100/80 px-4 py-2.5 border-b border-slate-200">
              <span className="text-xs font-bold uppercase text-slate-700 tracking-wider">REST API Endpoints Reference</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold uppercase text-[10px]">
                  <tr>
                    <th className="py-2 px-4">Method</th>
                    <th className="py-2 px-4">Endpoint</th>
                    <th className="py-2 px-4">Description</th>
                    <th className="py-2 px-4">Auth</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  <tr>
                    <td className="py-2 px-4 text-emerald-700 font-bold">POST</td>
                    <td className="py-2 px-4 text-slate-800">/api/files</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Upload single file for queued analysis</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-emerald-700 font-bold">POST</td>
                    <td className="py-2 px-4 text-slate-800">/api/files/fetch-url</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Fetch file from remote URL with SSRF boundary check</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-blue-700 font-bold">GET</td>
                    <td className="py-2 px-4 text-slate-800">/api/jobs/{'{id}'}</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Get job state, progress percentage, and current step</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-blue-700 font-bold">GET</td>
                    <td className="py-2 px-4 text-slate-800">/api/jobs/{'{id}'}/analysis</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Full security findings, risk assessment, hashes, AV, YARA</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-blue-700 font-bold">GET</td>
                    <td className="py-2 px-4 text-slate-800">/api/jobs/{'{id}'}/metadata</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Structured metadata (general, EXIF, GPS, camera, embedded)</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-blue-700 font-bold">GET</td>
                    <td className="py-2 px-4 text-slate-800">/api/jobs/{'{id}'}/urls</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Extracted URLs, TLS certificates, and live screenshots</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-emerald-700 font-bold">POST</td>
                    <td className="py-2 px-4 text-slate-800">/api/jobs/{'{id}'}/sanitize</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Trigger Content Disarm & Reconstruction (CDR)</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-blue-700 font-bold">GET</td>
                    <td className="py-2 px-4 text-slate-800">/api/jobs/{'{id}'}/download</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Download sanitized clean file</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Public</td>
                  </tr>
                  <tr>
                    <td className="py-2 px-4 text-emerald-700 font-bold">POST</td>
                    <td className="py-2 px-4 text-slate-800">/api/admin/login</td>
                    <td className="py-2 px-4 font-sans text-slate-600">Authenticate admin and receive bearer JWT token</td>
                    <td className="py-2 px-4 font-sans text-slate-400">Credentials</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Language Examples */}
          <div className="space-y-6">
            {/* Example: Python SDK */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/50">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-bold text-indigo-800 uppercase tracking-wider">
                  🐍 Python Automation Script (End-to-End Analysis & CDR)
                </h3>
                <span className="text-[10px] font-mono bg-indigo-100 text-indigo-800 px-2 py-0.5 rounded">Python 3.8+ (requests)</span>
              </div>
              <p className="text-xs text-slate-600 mb-3">
                Uploads a document, polls status until analysis finishes, evaluates the risk level, and triggers sanitization if threats are present:
              </p>
              <pre className="p-4 bg-white text-slate-800 rounded-xl font-mono text-xs overflow-x-auto leading-relaxed border border-slate-200 shadow-xs">
{`import time
import requests

API_BASE = "http://localhost:8000/api"

def sanitize_document(filepath: str, output_path: str):
    # 1. Upload file
    with open(filepath, "rb") as f:
        resp = requests.post(f"{API_BASE}/files", files={"files": f})
    resp.raise_for_status()
    job = resp.json()["jobs"][0]
    job_id = job["job_id"]
    print(f"Created Job {job_id} for '{job['filename']}'")

    # 2. Poll until analysis is ready
    while True:
        status_resp = requests.get(f"{API_BASE}/jobs/{job_id}").json()
        state = status_resp["state"]
        step = status_resp.get("current_step_label", "")
        progress = status_resp.get("progress", 0)
        print(f"[{progress}%] State: {state} - {step}")
        if state in ("ANALYZED", "COMPLETED", "FAILED"):
            break
        time.sleep(1)

    # 3. Inspect security findings & risk score
    analysis = requests.get(f"{API_BASE}/jobs/{job_id}/analysis").json()
    risk = analysis.get("risk", {})
    print(f"Risk Assessment: {risk.get('level')} (Score: {risk.get('score')}/100)")
    for finding in analysis.get("findings", []):
        print(f" - [{finding['severity'].upper()}] {finding['title']}")

    # 4. Trigger CDR Sanitization (Disarm active content, convert to safe PDF)
    sanitize_payload = {
        "profile": "maximum",
        "options": {
            "remove_macros": True,
            "remove_javascript": True,
            "remove_metadata": True,
            "convert_to_pdf": True
        }
    }
    requests.post(f"{API_BASE}/jobs/{job_id}/sanitize", json=sanitize_payload)

    # Wait for CDR completion
    while True:
        s = requests.get(f"{API_BASE}/jobs/{job_id}").json()["state"]
        if s == "COMPLETED":
            break
        time.sleep(0.5)

    # 5. Download disarmed file
    clean_bytes = requests.get(f"{API_BASE}/jobs/{job_id}/download").content
    with open(output_path, "wb") as f_out:
        f_out.write(clean_bytes)
    print(f"✓ Disarmed file saved to {output_path}")

sanitize_document("contract.docx", "contract_clean.pdf")`}
              </pre>
            </div>

            {/* Example: JavaScript / Node.js */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/50">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-bold text-indigo-800 uppercase tracking-wider">
                  🌐 JavaScript / Node.js (Fetch API)
                </h3>
                <span className="text-[10px] font-mono bg-amber-100 text-amber-800 px-2 py-0.5 rounded">Node 18+ / Browser</span>
              </div>
              <p className="text-xs text-slate-600 mb-3">
                Stateless async/await workflow using standard web <code className="font-mono text-slate-800">fetch</code> and <code className="font-mono text-slate-800">FormData</code>:
              </p>
              <pre className="p-4 bg-white text-slate-800 rounded-xl font-mono text-xs overflow-x-auto leading-relaxed border border-slate-200 shadow-xs">
{`async function analyzeAndCleanFile(fileBlob, filename) {
  const formData = new FormData();
  formData.append('files', fileBlob, filename);

  // 1. Upload
  const uploadRes = await fetch('http://localhost:8000/api/files', {
    method: 'POST',
    body: formData,
  }).then(r => r.json());

  const jobId = uploadRes.jobs[0].job_id;

  // 2. Poll status
  let jobState = 'QUEUED';
  while (jobState !== 'ANALYZED' && jobState !== 'COMPLETED') {
    await new Promise(r => setTimeout(r, 1000));
    const status = await fetch(\`http://localhost:8000/api/jobs/\${jobId}\`).then(r => r.json());
    jobState = status.state;
  }

  // 3. Retrieve findings
  const analysis = await fetch(\`http://localhost:8000/api/jobs/\${jobId}/analysis\`).then(r => r.json());
  console.log('Risk Level:', analysis.risk.level);

  // 4. Download disarmed file directly
  const downloadUrl = \`http://localhost:8000/api/jobs/\${jobId}/download\`;
  window.open(downloadUrl, '_blank');
}`}
              </pre>
            </div>

            {/* Example: CI/CD Security Gate (GitHub Actions) */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/50">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-bold text-indigo-800 uppercase tracking-wider">
                  ⚙️ CI/CD Security Gate (GitHub Actions Pipeline)
                </h3>
                <span className="text-[10px] font-mono bg-purple-100 text-purple-800 px-2 py-0.5 rounded">GitHub Actions YAML</span>
              </div>
              <p className="text-xs text-slate-600 mb-3">
                Automatically scans committed documents or artifacts in pull requests and fails the build if malicious active content is found:
              </p>
              <pre className="p-4 bg-white text-slate-800 rounded-xl font-mono text-xs overflow-x-auto leading-relaxed border border-slate-200 shadow-xs">
{`name: FileSanitizer Security Inspection

on: [push, pull_request]

jobs:
  inspect-artifacts:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Scan Office & PDF Artifacts
        run: |
          for f in docs/*.pdf docs/*.docx; do
            [ -f "$f" ] || continue
            echo "Scanning $f..."
            JOB_ID=$(curl -s -F "files=@$f" http://sanitizer.internal/api/files | jq -r '.jobs[0].job_id')
            
            # Poll status
            while true; do
              STATE=$(curl -s http://sanitizer.internal/api/jobs/$JOB_ID | jq -r '.state')
              [ "$STATE" = "ANALYZED" ] && break
              sleep 1
            done

            RISK=$(curl -s http://sanitizer.internal/api/jobs/$JOB_ID/analysis | jq -r '.risk.level')
            echo "$f Risk Level: $RISK"
            if [ "$RISK" = "MALICIOUS" ] || [ "$RISK" = "HIGH RISK" ]; then
              echo "::error file=$f::Blocked: Document failed security gate ($RISK)"
              exit 1
            fi
          done`}
              </pre>
            </div>

            {/* Example: cURL & Payload Schemas */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/50">
              <h3 className="text-xs font-bold text-indigo-800 uppercase tracking-wider mb-2">
                📡 cURL Commands & Payload Schemas
              </h3>
              <div className="space-y-3 mt-3">
                <div>
                  <span className="text-[11px] font-mono text-slate-700 font-bold block mb-1">Upload File:</span>
                  <pre className="p-3 bg-white text-slate-800 rounded-xl font-mono text-xs overflow-x-auto border border-slate-200 shadow-xs">
{`curl -X POST http://localhost:8000/api/files -F "files=@sample.pdf"`}
                  </pre>
                </div>

                <div>
                  <span className="text-[11px] font-mono text-slate-700 font-bold block mb-1">Trigger Disarm with Custom Options:</span>
                  <pre className="p-3 bg-white text-slate-800 rounded-xl font-mono text-xs overflow-x-auto border border-slate-200 shadow-xs">
{`curl -X POST http://localhost:8000/api/jobs/<JOB_ID>/sanitize \\
  -H "Content-Type: application/json" \\
  -d '{
    "profile": "maximum",
    "options": {
      "remove_macros": true,
      "remove_javascript": true,
      "remove_metadata": true,
      "convert_to_png": true
    }
  }'`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB: Archive Auto-Unlocking Pipeline Dictionary */}
      {activeTab === 'archive_passwords' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>🔓</span> Archive Decryption & Auto-Unlocking Dictionary
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Candidate dictionary automatically tried against encrypted ZIP and RAR malware archives during ingestion
              </p>
            </div>
            <button
              type="button"
              onClick={handleResetArchivePasswords}
              className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer self-start sm:self-auto"
            >
              Reset to Defaults
            </button>
          </div>

          {archivePasswordMsg && (
            <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
              <span>{archivePasswordMsg}</span>
            </div>
          )}

          {/* Educational context */}
          <div className="p-4 bg-indigo-50/60 border border-indigo-100 rounded-2xl text-xs text-indigo-950 space-y-1 leading-relaxed">
            <span className="font-bold flex items-center gap-1.5 text-indigo-900">
              <span>💡</span> How Automated Archive Decryption Operates
            </span>
            <p>
              When a password-protected archive is submitted, the ingestion pipeline sequentially tests candidate passwords from this dictionary.
              If decryption succeeds, the internal files are unpacked, scanned for malicious content, and sanitized transparently.
              Common threat hunting passwords (e.g. <code className="bg-white px-1.5 py-0.5 rounded font-mono text-[11px]">infected</code>, <code className="bg-white px-1.5 py-0.5 rounded font-mono text-[11px]">malware</code>, <code className="bg-white px-1.5 py-0.5 rounded font-mono text-[11px]">password</code>) are active by default.
            </p>
          </div>

          {/* Add Password Form */}
          <form onSubmit={handleAddArchivePassword} className="flex gap-2">
            <input
              type="text"
              value={newArchivePasswordInput}
              onChange={(e) => setNewArchivePasswordInput(e.target.value)}
              placeholder="Enter new candidate password (e.g. campaign_2026, rules, infected)..."
              className="flex-1 bg-slate-50 border border-slate-300 rounded-xl px-4 py-2.5 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
            />
            <button
              type="submit"
              disabled={!newArchivePasswordInput.trim()}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-xs transition-all cursor-pointer shrink-0"
            >
              + Add Password
            </button>
          </form>

          {/* Passwords List */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-500 font-semibold px-1">
              <span>Active Dictionary Passwords ({archivePasswords.length})</span>
              <span>Priority: Sequential Ingestion Order</span>
            </div>

            {isLoadingArchivePasswords ? (
              <div className="p-8 text-center text-slate-400 bg-slate-50 border border-slate-200 rounded-2xl animate-pulse">
                Loading archive password dictionary...
              </div>
            ) : archivePasswords.length > 0 ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                {archivePasswords.map((pw, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-50 hover:bg-slate-100/80 border border-slate-200 rounded-xl flex items-center justify-between gap-2 transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-5 h-5 rounded-full bg-white border border-slate-200 text-slate-500 text-[10px] font-bold flex items-center justify-center shrink-0">
                        {idx + 1}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-800 truncate select-all">{pw}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleDeleteArchivePassword(pw)}
                      className="text-slate-400 hover:text-rose-600 p-1 rounded-lg transition-colors cursor-pointer shrink-0"
                      title={`Remove "${pw}"`}
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400 bg-slate-50 border border-slate-200 rounded-2xl">
                No archive unlocking passwords configured. Encrypted archives will prompt for manual password input.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB: Threat Intelligence & External API Cache Management */}
      {activeTab === 'cache' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>⚡</span> External API Intelligence Caching & Lifetime Policy
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Persistent SQLite + Redis accelerator for Shodan, VirusTotal, ThreatFox, URLhaus, WHOIS, and Google Dork scans
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={fetchCacheStats}
                disabled={isLoadingCache}
                className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                {isLoadingCache ? 'Refreshing...' : '↻ Refresh Stats'}
              </button>
              <button
                type="button"
                onClick={() => handleClearCache()}
                className="px-3.5 py-1.5 bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Flush All Cache
              </button>
            </div>
          </div>

          {cacheMsg && (
            <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
              <span>{cacheMsg}</span>
            </div>
          )}

          {/* External API Cache Policy & Lifetime Configuration */}
          <div className="p-5 bg-gradient-to-r from-blue-50/50 to-indigo-50/50 border border-blue-200/80 rounded-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <span>🗄️</span> External API Caching Strategy & Expiration Policy
                </h4>
                <p className="text-xs text-slate-600 mt-0.5">
                  Configure whether third-party intelligence queries (Shodan, VirusTotal, URLhaus, CTI) should reuse cached data or fetch fresh live telemetry.
                </p>
              </div>
              <button
                type="button"
                onClick={handleSaveCachePolicy}
                disabled={isSavingCachePolicy}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl shadow-sm transition-all cursor-pointer flex items-center gap-1.5"
              >
                {isSavingCachePolicy ? 'Saving...' : '💾 Save Cache Policy'}
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
              {/* Option 1: Reuse Cached Data */}
              <label
                onClick={() => setCacheMode('use_cache')}
                className={`p-4 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                  cacheMode === 'use_cache'
                    ? 'bg-white border-blue-500 shadow-sm ring-1 ring-blue-500'
                    : 'bg-white/60 border-slate-200 hover:bg-white'
                }`}
              >
                <input
                  type="radio"
                  name="cache_mode"
                  checked={cacheMode === 'use_cache'}
                  onChange={() => setCacheMode('use_cache')}
                  className="mt-1 text-blue-600 focus:ring-blue-500"
                />
                <div className="space-y-1">
                  <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                    <span>Reuse Cached Intelligence</span>
                    <span className="px-2 py-0.2 rounded-full text-[10px] bg-emerald-100 text-emerald-800 font-semibold uppercase">Recommended</span>
                  </div>
                  <p className="text-[11px] text-slate-500 leading-relaxed">
                    Saves API query credits, avoids rate limits, and speeds up analysis by serving cached responses if newer than your threshold.
                  </p>
                </div>
              </label>

              {/* Option 2: Always Fetch Fresh Data */}
              <label
                onClick={() => setCacheMode('always_fetch')}
                className={`p-4 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                  cacheMode === 'always_fetch'
                    ? 'bg-white border-blue-500 shadow-sm ring-1 ring-blue-500'
                    : 'bg-white/60 border-slate-200 hover:bg-white'
                }`}
              >
                <input
                  type="radio"
                  name="cache_mode"
                  checked={cacheMode === 'always_fetch'}
                  onChange={() => setCacheMode('always_fetch')}
                  className="mt-1 text-blue-600 focus:ring-blue-500"
                />
                <div className="space-y-1">
                  <div className="text-xs font-bold text-slate-900">Always Fetch Live Data</div>
                  <p className="text-[11px] text-slate-500 leading-relaxed">
                    Bypasses all cached intelligence on every scan and queries external APIs directly for real-time live telemetry.
                  </p>
                </div>
              </label>
            </div>

            {/* Threshold Settings (Visible if use_cache is active) */}
            {cacheMode === 'use_cache' && (
              <div className="p-4 bg-white rounded-xl border border-blue-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-0.5">
                  <label className="text-xs font-bold text-slate-800">
                    Max Cache Age Threshold (Data Expiration)
                  </label>
                  <p className="text-[11px] text-slate-500">
                    External API data older than this threshold will be considered expired and re-fetched live on demand.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-600 font-medium">Expire after:</span>
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={cacheMaxAgeValue}
                    onChange={(e) => setCacheMaxAgeValue(Math.max(1, parseInt(e.target.value) || 1))}
                    className="w-20 px-3 py-1.5 text-xs font-mono font-semibold bg-slate-50 border border-slate-300 rounded-lg text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 text-center"
                  />
                  <select
                    value={cacheMaxAgeUnit}
                    onChange={(e) => setCacheMaxAgeUnit(e.target.value as any)}
                    className="px-3 py-1.5 text-xs font-semibold bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
                  >
                    <option value="hours">Hour(s)</option>
                    <option value="days">Day(s)</option>
                  </select>
                </div>
              </div>
            )}
          </div>

          {/* Connection Status Banner */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className={`p-4 rounded-2xl border flex items-center justify-between ${
              cacheStats?.connected
                ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                : 'bg-amber-50 border-amber-200 text-amber-900'
            }`}>
              <div className="flex items-center gap-3">
                <span className={`w-3 h-3 rounded-full ${cacheStats?.connected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
                <div>
                  <span className="text-xs font-bold uppercase tracking-wider block">
                    {cacheStats?.connected ? 'Redis Accelerator: Operational (Online)' : 'Redis Offline (In-Memory Fallback)'}
                  </span>
                  <span className="text-[11px] text-slate-600 font-mono">
                    {cacheStats?.connected ? 'redis://filesanitizer-redis:6379/0' : 'SQLite persistent layer active.'}
                  </span>
                </div>
              </div>
              {cacheStats?.used_memory_human && (
                <span className="text-xs font-mono font-semibold px-2.5 py-1 bg-white rounded-lg border border-slate-200">
                  Memory: {cacheStats.used_memory_human}
                </span>
              )}
            </div>

            <div className="p-4 rounded-2xl border bg-slate-50 border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="w-3 h-3 rounded-full bg-blue-500" />
                <div>
                  <span className="text-xs font-bold text-slate-900 uppercase tracking-wider block">
                    Persistent SQLite Database
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    /jobs/config/external_api_cache.sqlite
                  </span>
                </div>
              </div>
              <span className="text-xs font-mono font-semibold px-2.5 py-1 bg-white rounded-lg border border-slate-200">
                Size: {cacheStats?.db_size_bytes ? `${(cacheStats.db_size_bytes / 1024).toFixed(1)} KB` : 'Active'}
              </span>
            </div>
          </div>

          {/* Cache Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-1">Total Cached Queries</span>
              <span className="text-2xl font-black text-slate-900 font-mono">
                {cacheStats?.total_items || cacheStats?.total_cached_items || 0}
              </span>
              <span className="text-[10px] text-slate-400 block mt-1">Durable records stored on disk</span>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-1">Cache Hit Ratio</span>
              <span className="text-2xl font-black text-indigo-600 font-mono">
                {cacheStats?.hit_ratio ?? 0}%
              </span>
              <span className="text-[10px] text-slate-400 block mt-1">Quota & API lookups spared</span>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-1">Cache Hits</span>
              <span className="text-2xl font-black text-emerald-600 font-mono">
                {cacheStats?.hits ?? 0}
              </span>
              <span className="text-[10px] text-slate-400 block mt-1">Instant local responses</span>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block mb-1">Cache Misses</span>
              <span className="text-2xl font-black text-slate-600 font-mono">
                {cacheStats?.misses ?? 0}
              </span>
              <span className="text-[10px] text-slate-400 block mt-1">Live external API queries</span>
            </div>
          </div>

          {/* Granular Cache Flush Controls */}
          <div className="p-5 bg-slate-50 border border-slate-200 rounded-2xl space-y-3">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Granular Intelligence Cache Invalidation
            </h4>
            <p className="text-xs text-slate-500">
              Flush individual intelligence feeds when new threat signatures are published or to force live re-indexing:
            </p>
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                type="button"
                onClick={() => handleClearCache('shodan_domain')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear Shodan Domain Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('shodan_ip')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear Shodan IP Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('threat_intel')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear Threat Intel Feeds
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('dork_scan')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear Google Dorks Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('virustotal')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear VirusTotal Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('threatfox')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear ThreatFox Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('malwarebazaar')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear MalwareBazaar Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('alienvault_otx')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear AlienVault OTX Cache
              </button>
              <button
                type="button"
                onClick={() => handleClearCache('network')}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Clear WHOIS & GeoIP Cache
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB: Format-Specific CDR & Sanitization Policies */}
      {activeTab === 'cdr_policies' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>🛡️</span> Sanitization & Content Disarm & Reconstruction (CDR) Policies
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Configure whether Sanitization & CDR is enabled per file format, which sanitization transformations are permitted, and allowed output conversion formats.
              </p>
            </div>
            <button
              type="button"
              onClick={fetchCdrPolicies}
              disabled={isLoadingCdrPolicies}
              className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer self-start sm:self-auto"
            >
              {isLoadingCdrPolicies ? 'Refreshing...' : '↻ Refresh Policies'}
            </button>
          </div>

          {cdrPolicyMsg && (
            <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
              <span>{cdrPolicyMsg}</span>
            </div>
          )}

          <div className="p-4 bg-blue-50/60 border border-blue-100 rounded-2xl text-xs text-blue-950 space-y-1.5 leading-relaxed">
            <span className="font-bold flex items-center gap-1.5 text-blue-900">
              <span>ℹ️</span> Per-Format CDR Governance Rules
            </span>
            <p>
              • If Sanitization & CDR is <strong>Disabled</strong> for a format, the "Sanitization & CDR" tab and "CDR Diff Inspector" are completely hidden from the analysis dashboard for files of that format.
            </p>
            <p>
              • Allowed options determine which disarm controls (stripping JavaScript, macro elimination, form flattening, rasterization, metadata purging) are presented to analysts.
            </p>
            <p>
              • Allowed output formats restrict the conversions permitted for users (e.g. converting Office documents or emails to static PDFs, or images to lossy/lossless formats).
            </p>
          </div>

          {/* Format Policies Grid */}
          <div className="space-y-4">
            {Object.keys(cdrPolicies).length === 0 ? (
              <div className="p-8 text-center text-slate-400 bg-slate-50 border border-slate-200 rounded-2xl animate-pulse">
                Loading format-specific CDR policies...
              </div>
            ) : (
              Object.entries(cdrPolicies).map(([fmtId, policy]: [string, any]) => {
                const isEnabled = policy.enabled !== false;
                const allowedOpts: string[] = policy.allowed_options || [];
                const allowedFmts: string[] = policy.allowed_output_formats || [];

                return (
                  <div
                    key={fmtId}
                    className={`border rounded-2xl p-5 transition-all ${
                      isEnabled
                        ? 'bg-white border-slate-200 shadow-2xs'
                        : 'bg-slate-50/70 border-slate-200 opacity-75'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
                      <div className="flex items-center gap-2.5">
                        <div className={`w-3 h-3 rounded-full ${isEnabled ? 'bg-emerald-500' : 'bg-slate-300'}`} />
                        <div>
                          <h4 className="font-bold text-slate-900 text-sm">{policy.format_name || fmtId}</h4>
                          <span className="text-[11px] font-mono text-slate-400 uppercase">Format ID: {fmtId}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <label className="flex items-center gap-2 cursor-pointer select-none">
                          <input
                            type="checkbox"
                            checked={isEnabled}
                            onChange={(e) => handleToggleCdrFormat(fmtId, e.target.checked)}
                            className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500 border-slate-300 cursor-pointer"
                          />
                          <span className={`text-xs font-bold ${isEnabled ? 'text-emerald-700' : 'text-slate-500'}`}>
                            {isEnabled ? 'CDR Enabled' : 'CDR Disabled (Hidden in UI)'}
                          </span>
                        </label>
                      </div>
                    </div>

                    {isEnabled && (
                      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                        {/* Allowed Disarm & Sanitization Options */}
                        <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                          <span className="font-bold text-slate-700 block uppercase tracking-wider text-[10px]">
                            Permitted Sanitization & Disarm Transformations
                          </span>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                            {[
                              { key: 'remove_metadata', label: 'Strip All Metadata' },
                              { key: 'remove_gps', label: 'Purge GPS Coordinates' },
                              { key: 'remove_author', label: 'Remove Author & Identity' },
                              { key: 'remove_timestamps', label: 'Normalize Timestamps' },
                              { key: 'remove_comments', label: 'Prune Comments / Revisions' },
                              { key: 'remove_embedded_files', label: 'Purge Embedded Files / OLE' },
                              { key: 'remove_macros', label: 'Eradicate VBA Macros' },
                              { key: 'remove_javascript', label: 'Neutralize Active JavaScript' },
                              { key: 'remove_external_links', label: 'Disarm External Hyperlinks' },
                              { key: 'reencode_image', label: 'Re-encode Pixel Buffer' },
                              { key: 'flatten_image', label: 'Flatten Transparency' },
                              { key: 'flatten_document', label: 'Flatten Forms & Annotations' },
                              { key: 'rasterize_pages', label: 'Deep Rasterize Pages (Image PDF)' },
                              { key: 'strip_active_content', label: 'Strip HTML/DOM Scripts' },
                              { key: 'strip_external_resources', label: 'Purge Remote Web Resources' }
                            ].map(opt => {
                              const isOptChecked = allowedOpts.includes(opt.key);
                              return (
                                <label key={opt.key} className="flex items-center gap-1.5 p-1 hover:bg-white rounded transition-colors cursor-pointer">
                                  <input
                                    type="checkbox"
                                    checked={isOptChecked}
                                    onChange={() => handleToggleCdrOption(fmtId, opt.key)}
                                    className="w-3.5 h-3.5 rounded text-indigo-600 focus:ring-indigo-500 border-slate-300 cursor-pointer"
                                  />
                                  <span className={isOptChecked ? 'text-slate-800 font-medium' : 'text-slate-400'}>
                                    {opt.label}
                                  </span>
                                </label>
                              );
                            })}
                          </div>
                        </div>

                        {/* Allowed Output Conversion Formats */}
                        <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                          <span className="font-bold text-slate-700 block uppercase tracking-wider text-[10px]">
                            Permitted Output Formats for Analysts
                          </span>
                          <div className="space-y-1.5">
                            {[
                              { key: 'original', label: 'Sanitized Native Container (Original Format)' },
                              { key: 'pdf', label: 'Hardened Static PDF Document' },
                              { key: 'png', label: 'Lossless Raster PNG Image' },
                              { key: 'jpg', label: 'Compressed Web JPEG Image' }
                            ].map(fmt => {
                              const isFmtChecked = allowedFmts.includes(fmt.key);
                              return (
                                <label key={fmt.key} className="flex items-center gap-2 p-1.5 hover:bg-white rounded-lg transition-colors cursor-pointer">
                                  <input
                                    type="checkbox"
                                    checked={isFmtChecked}
                                    onChange={() => handleToggleCdrOutputFormat(fmtId, fmt.key)}
                                    className="w-3.5 h-3.5 rounded text-blue-600 focus:ring-blue-500 border-slate-300 cursor-pointer"
                                  />
                                  <span className={`font-mono font-medium ${isFmtChecked ? 'text-slate-800' : 'text-slate-400'}`}>
                                    {fmt.label}
                                  </span>
                                </label>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* TAB: Windows Event Logs (EVTX) */}
      {activeTab === 'evtx' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-6">
          {/* Header */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-4 border-b border-slate-100 gap-4">
            <div>
              <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <span>🪵</span> Windows Event Logs (EVTX) Forensics & Monitoring Policies
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Configure which Windows Security, System, and Sysmon Event IDs are parsed into the forensic timeline, define custom threat severity classifications (Critical, High, Medium, Info), and govern incident response heuristics.
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                onClick={handleSelectAllCuratedEvtxIds}
                className="px-3 py-1.5 text-xs font-semibold bg-indigo-50 hover:bg-indigo-100 text-indigo-700 rounded-xl border border-indigo-200 transition-colors cursor-pointer"
                title="Activate all curated security & forensic baseline Event IDs"
              >
                ✓ Activate Curated ({CURATED_EVTX_EVENTS.length})
              </button>
              <button
                type="button"
                onClick={handleSelectAllKnownEvtxIds}
                className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl shadow-2xs transition-colors cursor-pointer"
                title="Activate all known Windows Event IDs (curated + extended)"
              >
                ✓ Activate All ({KNOWN_EVTX_EVENTS.length})
              </button>
              <button
                type="button"
                onClick={handleResetEvtxTimelineIds}
                className="px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl border border-slate-200 transition-colors cursor-pointer"
              >
                ↺ Reset Baseline
              </button>
              <button
                type="button"
                onClick={handleClearAllEvtxIds}
                className="px-3 py-1.5 text-xs font-semibold bg-rose-50 hover:bg-rose-100 text-rose-700 rounded-xl border border-rose-200 transition-colors cursor-pointer"
              >
                ✕ Clear All
              </button>
            </div>
          </div>

          {/* IR & Detection Engine Toggles */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-3">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">
              Windows Event Inspection Engines & Threat Heuristics
            </span>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {[
                { key: 'check_log_clearing', label: 'Anti-Forensics & Log Clearing (1102 / 104)' },
                { key: 'check_privilege_escalation', label: 'Privilege Escalation & Admin Tokens (4672 / 4728 / 4732)' },
                { key: 'check_ransomware_indicators', label: 'Ransomware Staging & Shadow Copy Deletion' },
                { key: 'check_account_manipulation', label: 'Backdoor & Rogue Account Creation (4720)' },
                { key: 'check_powershell_scriptblocks', label: 'PowerShell Script Block Logging (4104)' },
                { key: 'check_scheduled_tasks', label: 'Persistence via Scheduled Tasks (4698)' },
                { key: 'check_process_spawning', label: 'LOLBin & Process Execution (4688 / Sysmon 1)' },
                { key: 'check_network_connections', label: 'Network Connections & SMB Lateral Movement (5145 / 3)' },
                { key: 'check_defender_tampering', label: 'Microsoft Defender Tampering (5001 / 1116)' },
              ].map((engine) => {
                const isChecked = settingsData?.format_checks?.evtx?.[engine.key] !== false;
                return (
                  <label
                    key={engine.key}
                    className="flex items-center gap-2 p-2 bg-white rounded-xl border border-slate-200 hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => handleToggleCheck('evtx', engine.key, isChecked)}
                      className="w-4 h-4 rounded text-indigo-600 focus:ring-indigo-500 border-slate-300 cursor-pointer shrink-0"
                    />
                    <span className={`text-xs font-medium ${isChecked ? 'text-slate-800' : 'text-slate-400'}`}>
                      {engine.label}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Search, Grouping & Category Filter Bar */}
          {(() => {
            const activeIds: number[] = settingsData?.evtx_timeline_event_ids || DEFAULT_EVTX_BASELINE_IDS;
            const allCategories = Array.from(new Set(KNOWN_EVTX_EVENTS.map((e) => e.category))).sort();

            const filterFn = (evt: KnownEvtxEvent) => {
              if (evtxCategoryFilter !== 'all' && evt.category !== evtxCategoryFilter) return false;
              if (!evtxSearch.trim()) return true;
              const q = evtxSearch.toLowerCase();
              return (
                String(evt.id).includes(q) ||
                evt.name.toLowerCase().includes(q) ||
                evt.category.toLowerCase().includes(q) ||
                evt.desc.toLowerCase().includes(q)
              );
            };

            const knownIdsSet = new Set(KNOWN_EVTX_EVENTS.map((e) => e.id));
            const customActiveEvents: KnownEvtxEvent[] = activeIds
              .filter((id) => !knownIdsSet.has(id))
              .map((id) => ({
                id,
                name: `Custom Event ID ${id}`,
                category: 'Custom / User Defined',
                desc: 'Custom user-specified Windows Event ID configured for timeline monitoring.',
                severity: (settingsData?.evtx_severity_rules?.[String(id)] as any) || 'medium',
                isCurated: true,
              }));

            // DYNAMIC PARTITION:
            // - If a card's checkbox is checked (in activeIds), it is placed under Curated Security & Forensic Event IDs
            // - If a card's checkbox is unchecked (not in activeIds), it is placed under Standard & Extended Windows Event IDs
            const curatedEvents = [...KNOWN_EVTX_EVENTS.filter((e) => activeIds.includes(e.id)), ...customActiveEvents];
            const extendedEvents = KNOWN_EVTX_EVENTS.filter((e) => !activeIds.includes(e.id));

            const filteredCurated = curatedEvents.filter(filterFn);
            const filteredExtended = extendedEvents.filter(filterFn);

            return (
              <div className="space-y-6">
                {/* Filter Toolbar */}
                <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <div className="flex items-center bg-white border border-slate-200 rounded-xl p-0.5 text-xs font-semibold">
                      <button
                        type="button"
                        onClick={() => setEvtxGroupTab('both')}
                        className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                          evtxGroupTab === 'both' ? 'bg-indigo-600 text-white shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        All Groups ({filteredCurated.length + filteredExtended.length})
                      </button>
                      <button
                        type="button"
                        onClick={() => setEvtxGroupTab('curated')}
                        className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                          evtxGroupTab === 'curated' ? 'bg-indigo-600 text-white shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        🛡️ Curated ({filteredCurated.length})
                      </button>
                      <button
                        type="button"
                        onClick={() => setEvtxGroupTab('extended')}
                        className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                          evtxGroupTab === 'extended' ? 'bg-indigo-600 text-white shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        📋 Extended ({filteredExtended.length})
                      </button>
                    </div>

                    <select
                      value={evtxCategoryFilter}
                      onChange={(e) => setEvtxCategoryFilter(e.target.value)}
                      className="px-2.5 py-1 bg-white border border-slate-200 rounded-xl text-xs font-medium text-slate-700 cursor-pointer"
                    >
                      <option value="all">All Categories ({allCategories.length})</option>
                      {allCategories.map((cat) => (
                        <option key={cat} value={cat}>
                          {cat}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className="relative w-full sm:w-64">
                      <input
                        type="text"
                        value={evtxSearch}
                        onChange={(e) => setEvtxSearch(e.target.value)}
                        placeholder="Search Event ID, name, desc..."
                        className="w-full px-3 py-1 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
                      />
                      {evtxSearch && (
                        <button
                          onClick={() => setEvtxSearch('')}
                          className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs"
                        >
                          ✕
                        </button>
                      )}
                    </div>

                    <span className="px-2.5 py-1 rounded-xl text-xs font-bold bg-indigo-100 text-indigo-800 font-mono shrink-0">
                      {activeIds.length} Total Monitored
                    </span>
                  </div>
                </div>

                {/* GROUP 1: Curated Security & Forensic Event IDs */}
                {(evtxGroupTab === 'both' || evtxGroupTab === 'curated') && (
                  <div className="space-y-3.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-200 gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-slate-900 flex items-center gap-1.5">
                          <span>🛡️</span> Curated Security &amp; Forensic Event IDs
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 font-mono">
                          {filteredCurated.length} of {curatedEvents.length} Active / Monitored
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={handleResetEvtxTimelineIds}
                          className="px-2.5 py-1 text-[11px] font-semibold bg-indigo-50 text-indigo-700 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition-colors cursor-pointer"
                          title="Restore default curated baseline"
                        >
                          Reset Baseline
                        </button>
                        <button
                          type="button"
                          onClick={handleDeselectCuratedEvtxIds}
                          className="px-2.5 py-1 text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 rounded-lg border border-slate-200 transition-colors cursor-pointer"
                          title="Uncheck and move all cards to Standard & Extended"
                        >
                          Deselect All Active
                        </button>
                      </div>
                    </div>

                    <p className="text-xs text-slate-500">
                      Active forensic audit trail: All checked Event IDs are actively monitored and parsed into the forensic timeline. Uncheck any card's checkbox to move it to Standard &amp; Extended Windows Event IDs.
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {filteredCurated.map((evt) => {
                        const isChecked = true;
                        const customSev = settingsData?.evtx_severity_rules?.[String(evt.id)];
                        const currentSev = customSev || evt.severity || 'info';

                        return (
                          <div
                            key={evt.id}
                            className="flex flex-col justify-between p-3.5 rounded-2xl border transition-all bg-white border-indigo-200 shadow-2xs ring-1 ring-indigo-500/10"
                          >
                            <div>
                              <div className="flex items-center justify-between gap-2 mb-1.5">
                                <label className="flex items-center gap-2 cursor-pointer select-none">
                                  <input
                                    type="checkbox"
                                    checked={isChecked}
                                    onChange={() => handleToggleEvtxTimelineId(evt.id)}
                                    className="w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500 cursor-pointer"
                                  />
                                  <span className="font-mono text-xs font-bold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-lg border border-slate-200">
                                    ID {evt.id}
                                  </span>
                                </label>

                                <div className="flex items-center gap-1">
                                  <span className="text-[10px] text-slate-400 font-semibold uppercase">Severity:</span>
                                  <select
                                    value={currentSev}
                                    onChange={(e) => handleChangeEvtxSeverity(evt.id, e.target.value)}
                                    className={`text-[10px] font-bold uppercase rounded-lg px-2 py-1 border transition-colors cursor-pointer ${
                                      currentSev === 'critical' ? 'bg-rose-100 text-rose-800 border-rose-300' :
                                      currentSev === 'high' ? 'bg-orange-100 text-orange-800 border-orange-300' :
                                      currentSev === 'medium' ? 'bg-amber-100 text-amber-800 border-amber-300' :
                                      currentSev === 'low' ? 'bg-blue-100 text-blue-800 border-blue-300' :
                                      'bg-slate-100 text-slate-700 border-slate-300'
                                    }`}
                                  >
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                    <option value="info">Info</option>
                                  </select>
                                </div>
                              </div>

                              <h4 className="text-xs font-bold text-slate-900">{evt.name}</h4>
                              <p className="text-[11px] text-slate-500 mt-1 line-clamp-2" title={evt.desc}>
                                {evt.desc}
                              </p>
                            </div>

                            <div className="mt-3 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px]">
                              <span className="font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">
                                {evt.category}
                              </span>
                              <span className="text-indigo-600 font-bold">
                                ● In Timeline
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* GROUP 2: Standard & Extended Windows Event IDs */}
                {(evtxGroupTab === 'both' || evtxGroupTab === 'extended') && (
                  <div className="space-y-3.5 pt-4 border-t border-slate-200">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-200 gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-slate-900 flex items-center gap-1.5">
                          <span>📋</span> Standard &amp; Extended Windows Event IDs
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200 font-mono">
                          {filteredExtended.length} of {extendedEvents.length} Available / Inactive
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={handleSelectAllExtendedEvtxIds}
                          className="px-2.5 py-1 text-[11px] font-semibold bg-purple-50 text-purple-700 hover:bg-purple-100 rounded-lg border border-purple-200 transition-colors cursor-pointer"
                          title="Check and move all extended cards to Curated"
                        >
                          Activate All Extended
                        </button>
                      </div>
                    </div>

                    <p className="text-xs text-slate-500">
                      Standard Windows system, Active Directory replication, Certificate Services (ADCS), Print Spooler, WFP firewall, and service control events. Check any card's checkbox to immediately move it to Curated Security &amp; Forensic Event IDs and start monitoring.
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {filteredExtended.map((evt) => {
                        const isChecked = false;
                        const customSev = settingsData?.evtx_severity_rules?.[String(evt.id)];
                        const currentSev = customSev || evt.severity || 'info';

                        return (
                          <div
                            key={evt.id}
                            className="flex flex-col justify-between p-3.5 rounded-2xl border transition-all bg-slate-50/60 border-slate-200 opacity-70 hover:opacity-100"
                          >
                            <div>
                              <div className="flex items-center justify-between gap-2 mb-1.5">
                                <label className="flex items-center gap-2 cursor-pointer select-none">
                                  <input
                                    type="checkbox"
                                    checked={isChecked}
                                    onChange={() => handleToggleEvtxTimelineId(evt.id)}
                                    className="w-4 h-4 text-purple-600 rounded border-slate-300 focus:ring-purple-500 cursor-pointer"
                                  />
                                  <span className="font-mono text-xs font-bold text-slate-900 bg-slate-100 px-2 py-0.5 rounded-lg border border-slate-200">
                                    ID {evt.id}
                                  </span>
                                </label>

                                <div className="flex items-center gap-1">
                                  <span className="text-[10px] text-slate-400 font-semibold uppercase">Severity:</span>
                                  <select
                                    value={currentSev}
                                    onChange={(e) => handleChangeEvtxSeverity(evt.id, e.target.value)}
                                    className={`text-[10px] font-bold uppercase rounded-lg px-2 py-1 border transition-colors cursor-pointer ${
                                      currentSev === 'critical' ? 'bg-rose-100 text-rose-800 border-rose-300' :
                                      currentSev === 'high' ? 'bg-orange-100 text-orange-800 border-orange-300' :
                                      currentSev === 'medium' ? 'bg-amber-100 text-amber-800 border-amber-300' :
                                      currentSev === 'low' ? 'bg-blue-100 text-blue-800 border-blue-300' :
                                      'bg-slate-100 text-slate-700 border-slate-300'
                                    }`}
                                  >
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                    <option value="info">Info</option>
                                  </select>
                                </div>
                              </div>

                              <h4 className="text-xs font-bold text-slate-900">{evt.name}</h4>
                              <p className="text-[11px] text-slate-500 mt-1 line-clamp-2" title={evt.desc}>
                                {evt.desc}
                              </p>
                            </div>

                            <div className="mt-3 pt-2 border-t border-slate-100 flex items-center justify-between text-[10px]">
                              <span className="font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">
                                {evt.category}
                              </span>
                              <span className="text-slate-400 font-medium">
                                ○ Excluded
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {/* Custom Event ID Addition & Management */}
          <div className="pt-4 border-t border-slate-100 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Register Custom Monitored Windows Event IDs
                </h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Monitor proprietary applications, custom event providers, or third-party audit channels.
                </p>
              </div>

              <form onSubmit={handleAddCustomEvtxId} className="flex items-center gap-2 flex-wrap">
                <input
                  type="number"
                  min="1"
                  max="65535"
                  value={customEvtxIdInput}
                  onChange={(e) => setCustomEvtxIdInput(e.target.value)}
                  placeholder="Event ID (e.g. 4738, 5142)"
                  className="w-40 px-3 py-1.5 text-xs bg-slate-50 border border-slate-300 rounded-xl focus:outline-hidden focus:ring-1 focus:ring-indigo-500 font-mono"
                />
                <select
                  value={customEvtxSeverity}
                  onChange={(e) => setCustomEvtxSeverity(e.target.value as any)}
                  className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-300 rounded-xl font-bold uppercase"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-colors cursor-pointer shadow-2xs"
                >
                  + Add Event ID
                </button>
              </form>
            </div>

            {/* Custom Event Chips */}
            {(() => {
              const activeIds: number[] = settingsData?.evtx_timeline_event_ids || DEFAULT_EVTX_BASELINE_IDS;
              const knownIds = new Set(KNOWN_EVTX_EVENTS.map((k) => k.id));
              const customIds = activeIds.filter((id) => !knownIds.has(id));

              if (customIds.length === 0) {
                return (
                  <p className="text-xs text-slate-400 italic bg-slate-50 p-3 rounded-xl border border-slate-200">
                    No custom Event IDs currently registered. Any non-standard event IDs added here will appear in the forensic event timeline.
                  </p>
                );
              }

              return (
                <div className="flex flex-wrap gap-2">
                  {customIds.map((id) => {
                    const sev = settingsData?.evtx_severity_rules?.[String(id)] || 'medium';
                    return (
                      <span
                        key={id}
                        className="inline-flex items-center gap-2 bg-indigo-50 border border-indigo-200 text-indigo-900 text-xs font-mono font-bold px-3 py-1.5 rounded-xl"
                      >
                        <span>Event {id}</span>
                        <select
                          value={sev}
                          onChange={(e) => handleChangeEvtxSeverity(id, e.target.value)}
                          className="text-[10px] font-bold uppercase bg-white border border-indigo-200 rounded px-1.5 py-0.5 cursor-pointer"
                        >
                          <option value="critical">Critical</option>
                          <option value="high">High</option>
                          <option value="medium">Medium</option>
                          <option value="low">Low</option>
                          <option value="info">Info</option>
                        </select>
                        <button
                          type="button"
                          onClick={() => handleToggleEvtxTimelineId(id)}
                          className="text-indigo-400 hover:text-rose-600 transition-colors cursor-pointer ml-1 text-sm font-bold"
                          title="Remove custom Event ID"
                        >
                          ✕
                        </button>
                      </span>
                    );
                  })}
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* TAB: Time & Localization Display Settings */}
      {activeTab === 'time' && (
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-7 shadow-sm space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
            <div>
              <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <span>🕒</span> Time Display &amp; Forensic Normalization
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Configure how timestamps across Forensic Event Timelines, EVTX logs, PCAP packet streams, and audit trails are formatted and normalized.
              </p>
            </div>
          </div>

          <form onSubmit={handleSaveTimeSettings} className="space-y-6 max-w-2xl">
            {/* Live Preview Box */}
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-1.5">
              <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">
                Live Timestamp Preview
              </span>
              <div className="text-lg font-mono font-bold text-indigo-700">
                {formatTimestamp(new Date().toISOString(), timeSettings)}
              </div>
              <span className="text-xs text-slate-500">
                This shows exactly how timestamps will be rendered across all forensic timeline cards and event tables.
              </span>
            </div>

            {/* 1. Time Format: 24h vs 12h */}
            <div className="space-y-2">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-700">
                Time Format (24-Hour vs 12-Hour)
              </label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setTimeSettings((prev: any) => ({ ...prev, format: '24h' }))}
                  className={`p-3.5 rounded-2xl border text-left transition-all cursor-pointer ${
                    timeSettings.format === '24h'
                      ? 'bg-indigo-50 border-indigo-300 ring-2 ring-indigo-500/20 shadow-xs'
                      : 'bg-white border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900">24-Hour Military Time</span>
                    <span className="text-xs">{timeSettings.format === '24h' ? '🔘' : '⚪'}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 block mt-1">
                    e.g. 14:30:45 (Forensic Standard)
                  </span>
                </button>

                <button
                  type="button"
                  onClick={() => setTimeSettings((prev: any) => ({ ...prev, format: '12h' }))}
                  className={`p-3.5 rounded-2xl border text-left transition-all cursor-pointer ${
                    timeSettings.format === '12h'
                      ? 'bg-indigo-50 border-indigo-300 ring-2 ring-indigo-500/20 shadow-xs'
                      : 'bg-white border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900">12-Hour AM/PM Time</span>
                    <span className="text-xs">{timeSettings.format === '12h' ? '🔘' : '⚪'}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 block mt-1">
                    e.g. 02:30:45 PM
                  </span>
                </button>
              </div>
            </div>

            {/* 2. Timezone Normalization */}
            <div className="space-y-2">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-700">
                Timezone Normalization
              </label>
              <p className="text-xs text-slate-500">
                Convert and align disparate server logs to a single coordinated timezone for accurate multi-log correlation.
              </p>
              <select
                value={timeSettings.time_zone}
                onChange={(e) => setTimeSettings((prev: any) => ({ ...prev, time_zone: e.target.value }))}
                className="w-full px-3.5 py-2.5 bg-white border border-slate-300 rounded-xl text-xs font-mono font-medium focus:outline-hidden focus:ring-2 focus:ring-indigo-500"
              >
                <option value="UTC">UTC (Coordinated Universal Time) — Recommended for Forensics</option>
                <option value="LOCAL">Local Browser Time ({Intl.DateTimeFormat().resolvedOptions().timeZone})</option>
                <option value="America/New_York">US Eastern Time (America/New_York - EST/EDT)</option>
                <option value="America/Chicago">US Central Time (America/Chicago - CST/CDT)</option>
                <option value="America/Denver">US Mountain Time (America/Denver - MST/MDT)</option>
                <option value="America/Los_Angeles">US Pacific Time (America/Los_Angeles - PST/PDT)</option>
                <option value="Europe/London">UK / Western Europe (Europe/London - GMT/BST)</option>
                <option value="Europe/Berlin">Central Europe (Europe/Berlin - CET/CEST)</option>
                <option value="Europe/Helsinki">Eastern Europe (Europe/Helsinki - EET/EEST)</option>
                <option value="Asia/Tokyo">Japan Standard Time (Asia/Tokyo - JST)</option>
                <option value="Asia/Singapore">Singapore Time (Asia/Singapore - SGT)</option>
                <option value="Asia/Dubai">Gulf Standard Time (Asia/Dubai - GST)</option>
                <option value="Australia/Sydney">Australian Eastern (Australia/Sydney - AEST/AEDT)</option>
              </select>
            </div>

            {/* 3. Toggles: Timezone Suffix & Milliseconds */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <label className="flex items-center gap-3 p-3.5 bg-slate-50 border border-slate-200 rounded-2xl cursor-pointer hover:bg-slate-100/70 transition-colors">
                <input
                  type="checkbox"
                  checked={timeSettings.show_timezone_suffix !== false}
                  onChange={(e) => setTimeSettings((prev: any) => ({ ...prev, show_timezone_suffix: e.target.checked }))}
                  className="w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500"
                />
                <div>
                  <span className="text-xs font-bold text-slate-900 block">Show Timezone Suffix</span>
                  <span className="text-[11px] text-slate-500">Append &quot;UTC&quot;, &quot;EST&quot;, or &quot;CET&quot; to timestamps</span>
                </div>
              </label>

              <label className="flex items-center gap-3 p-3.5 bg-slate-50 border border-slate-200 rounded-2xl cursor-pointer hover:bg-slate-100/70 transition-colors">
                <input
                  type="checkbox"
                  checked={Boolean(timeSettings.show_milliseconds)}
                  onChange={(e) => setTimeSettings((prev: any) => ({ ...prev, show_milliseconds: e.target.checked }))}
                  className="w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500"
                />
                <div>
                  <span className="text-xs font-bold text-slate-900 block">Include Milliseconds</span>
                  <span className="text-[11px] text-slate-500">Display high-precision .000ms in timeline</span>
                </div>
              </label>
            </div>

            {/* Submit button */}
            <div className="pt-4 border-t border-slate-100 flex items-center justify-end gap-3">
              <button
                type="submit"
                disabled={isSavingTimeSettings}
                className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold shadow-sm transition-all cursor-pointer"
              >
                {isSavingTimeSettings ? 'Saving...' : 'Save Time & Localization Settings'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL: YARA Rule Editor (Create & Edit) */}
      {showYaraModal && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowYaraModal(false);
          }}
        >
          <div
            className="bg-white border border-slate-200 rounded-3xl max-w-3xl w-full shadow-2xl animate-modal-fade flex flex-col max-h-[90vh] overflow-hidden my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  {editingYaraId ? '✏️ Edit YARA Rule' : '✨ Author New YARA Rule'}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Write, validate, and compile custom detection logic directly in your browser.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowYaraModal(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xl font-bold transition-colors"
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveYaraRule} className="flex flex-col flex-1 overflow-hidden min-h-0">
              <div className="p-6 overflow-y-auto flex-1 space-y-4">
                {yaraError && (
                  <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-700 text-xs flex items-center gap-2">
                    <span>⚠️</span>
                    <span>{yaraError}</span>
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="md:col-span-2">
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Rule Name</label>
                    <input
                      type="text"
                      required
                      value={yaraName}
                      onChange={(e) => setYaraName(e.target.value)}
                      placeholder="e.g. Detect Suspicious PowerShell Loader"
                      className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Target Format</label>
                    <select
                      value={yaraFormat}
                      onChange={(e) => setYaraFormat(e.target.value)}
                      className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                    >
                      <option value="ALL">ALL Formats</option>
                      <option value="PDF">PDF Documents</option>
                      <option value="OFFICE">Office Documents</option>
                      <option value="IMAGE">Images</option>
                      <option value="ARCHIVE">Archives (ZIP/TAR)</option>
                      <option value="SVG_HTML">SVG / HTML</option>
                      <option value="TEXT">Plaintext / CSV</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="md:col-span-2">
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Description</label>
                    <input
                      type="text"
                      value={yaraDesc}
                      onChange={(e) => setYaraDesc(e.target.value)}
                      placeholder="Summary of what this rule catches"
                      className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Severity</label>
                    <select
                      value={yaraSeverity}
                      onChange={(e) => setYaraSeverity(e.target.value)}
                      className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                    >
                      <option value="INFO">Informational</option>
                      <option value="LOW">Low Risk</option>
                      <option value="MEDIUM">Medium Risk</option>
                      <option value="HIGH">High Risk</option>
                      <option value="CRITICAL">Critical Exploit</option>
                    </select>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-semibold text-slate-700">YARA Source Code</label>
                    <button
                      type="button"
                      onClick={handleValidateYara}
                      disabled={isValidatingYara}
                      className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold flex items-center gap-1"
                    >
                      {isValidatingYara ? 'Validating...' : '✓ Test Syntax'}
                    </button>
                  </div>
                  <textarea
                    required
                    rows={9}
                    value={yaraText}
                    onChange={(e) => {
                      setYaraText(e.target.value);
                      setYaraValidation(null);
                    }}
                    className="w-full bg-slate-50 border border-slate-200 rounded-2xl p-4 text-xs text-slate-800 font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 leading-relaxed shadow-inner"
                  />
                </div>

                {yaraValidation && (
                  <div
                    className={`p-3 rounded-xl text-xs flex items-center gap-2 ${
                      yaraValidation.valid
                        ? 'bg-emerald-50 border border-emerald-200 text-emerald-800'
                        : 'bg-rose-50 border border-rose-200 text-rose-800'
                    }`}
                  >
                    <span>{yaraValidation.valid ? '✓' : '⚠️'}</span>
                    <span>
                      {yaraValidation.valid
                        ? 'YARA syntax compiled cleanly without errors.'
                        : `Compilation Error: ${yaraValidation.error}`}
                    </span>
                  </div>
                )}
              </div>

              <div className="px-6 py-3.5 bg-slate-50 border-t border-slate-100 flex justify-end gap-3 shrink-0 rounded-b-3xl">
                <button
                  type="button"
                  onClick={() => setShowYaraModal(false)}
                  className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium rounded-xl transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl shadow-md transition-all"
                >
                  {editingYaraId ? 'Save & Compile Changes' : 'Compile & Activate Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* MODAL: Warninglist Rule Editor (Create & Edit) */}
      {showWarningModal && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowWarningModal(false);
          }}
        >
          <div
            className="bg-white border border-slate-200 rounded-3xl max-w-lg w-full shadow-2xl animate-modal-fade flex flex-col max-h-[90vh] overflow-hidden my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  {editingWarningId ? '✏️ Edit Warning Rule' : '➕ Add Keyword / RegEx Rule'}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Scan document contents and metadata for sensitive phrases.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowWarningModal(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xl font-bold transition-colors"
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveWarningRule} className="flex flex-col flex-1 overflow-hidden min-h-0">
              <div className="p-6 overflow-y-auto flex-1 space-y-4">
                {warningError && (
                  <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-700 text-xs flex items-center gap-2">
                    <span>⚠️</span>
                    <span>{warningError}</span>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Rule Name / Trigger Label
                  </label>
                  <input
                    type="text"
                    required
                    value={warnName}
                    onChange={(e) => setWarnName(e.target.value)}
                    placeholder="e.g. Swedish Personnummer or Internal Account Key"
                    className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Search Pattern / Keyword
                  </label>
                  <input
                    type="text"
                    required
                    value={warnPattern}
                    onChange={(e) => setWarnPattern(e.target.value)}
                    placeholder={warnIsRegex ? 'e.g. \\b\\d{3}-\\d{2}-\\d{4}\\b' : 'e.g. confidential'}
                    className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs font-mono text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                  />
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="modal_is_regex"
                    checked={warnIsRegex}
                    onChange={(e) => setWarnIsRegex(e.target.checked)}
                    className="w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500"
                  />
                  <label htmlFor="modal_is_regex" className="text-xs font-medium text-slate-700 cursor-pointer">
                    Treat search pattern as a Regular Expression (RegEx)
                  </label>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Warning Severity</label>
                  <select
                    value={warnSeverity}
                    onChange={(e) => setWarnSeverity(e.target.value as any)}
                    className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                  >
                    <option value="informational">Informational</option>
                    <option value="low">Low Risk</option>
                    <option value="medium">Medium Risk</option>
                    <option value="high">High Risk</option>
                    <option value="critical">Critical Warning</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Description / Justification
                  </label>
                  <input
                    type="text"
                    value={warnDesc}
                    onChange={(e) => setWarnDesc(e.target.value)}
                    placeholder="e.g. Detects Social Security Number patterns in document bodies"
                    className="w-full bg-slate-50 border border-slate-300 rounded-xl px-3.5 py-2 text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
                  />
                </div>
              </div>

              <div className="px-6 py-3.5 bg-slate-50 border-t border-slate-100 flex justify-end gap-3 shrink-0 rounded-b-3xl">
                <button
                  type="button"
                  onClick={() => setShowWarningModal(false)}
                  className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium rounded-xl transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl shadow-md transition-all"
                >
                  {editingWarningId ? 'Save Changes' : 'Create Warning Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* MODAL: RegEx Guide & Examples */}
      {showRegexHelpModal && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowRegexHelpModal(false);
          }}
        >
          <div
            className="bg-white border border-slate-200 rounded-3xl max-w-2xl w-full shadow-2xl animate-modal-fade flex flex-col max-h-[85vh] overflow-hidden my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Pinned Modal Header */}
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-900">📖 Regular Expressions (RegEx) Guide</h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Learn regex syntax basics and use real-world security detection patterns.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowRegexHelpModal(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xl font-bold transition-colors"
                aria-label="Close RegEx Guide"
              >
                ✕
              </button>
            </div>

            {/* Scrollable Modal Content */}
            <div className="p-6 overflow-y-auto flex-1 space-y-5 text-xs text-slate-600">
              <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
                <h4 className="font-bold text-slate-800 uppercase tracking-wider mb-2">Core Syntax Cheat Sheet</h4>
                <div className="grid grid-cols-2 gap-2 text-slate-700 font-mono">
                  <div><code className="text-indigo-600 font-bold">\d</code> - Any digit (0-9)</div>
                  <div><code className="text-indigo-600 font-bold">\w</code> - Any word char (a-z, A-Z, 0-9)</div>
                  <div><code className="text-indigo-600 font-bold">\s</code> - Whitespace / space / tab</div>
                  <div><code className="text-indigo-600 font-bold">\b</code> - Word boundary</div>
                  <div><code className="text-indigo-600 font-bold">+</code> - One or more times</div>
                  <div><code className="text-indigo-600 font-bold">*</code> - Zero or more times</div>
                  <div><code className="text-indigo-600 font-bold">{'{3}'}</code> - Exactly 3 times</div>
                  <div><code className="text-indigo-600 font-bold">(?i)</code> - Case-insensitive match</div>
                </div>
              </div>

              <div>
                <h4 className="font-bold text-slate-800 uppercase tracking-wider mb-2.5">
                  Pre-Configured Security & Privacy Detection Patterns
                </h4>
                <div className="space-y-2.5">
                  {[
                    {
                      label: 'Swedish Personnummer (SSN / PNR)',
                      pattern: '\\b(19|20)?\\d{6}[-+]?\\d{4}\\b',
                      desc: 'Matches Swedish 10-digit and 12-digit personal identity numbers with optional hyphen or plus',
                      sev: 'high',
                    },
                    {
                      label: 'Credit Card Numbers',
                      pattern: '\\b(?:\\d{4}[ -]?){3}\\d{4}\\b',
                      desc: 'Matches 16-digit card sequences (Visa, MasterCard, Amex) with optional spaces or dashes',
                      sev: 'critical',
                    },
                    {
                      label: 'Email Addresses',
                      pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
                      desc: 'Detects email addresses in document content, author properties, or metadata',
                      sev: 'medium',
                    },
                    {
                      label: 'Swedish Organisationsnummer',
                      pattern: '\\b\\d{6}-\\d{4}\\b',
                      desc: 'Matches Swedish corporate registration numbers (organisationsnummer)',
                      sev: 'low',
                    },
                    {
                      label: 'International Bank Account Number (IBAN)',
                      pattern: '\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}\\b',
                      desc: 'Detects international bank account identifiers (IBAN format)',
                      sev: 'high',
                    },
                    {
                      label: 'JSON Web Token (JWT) / Bearer',
                      pattern: '\\beyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\b',
                      desc: 'Detects leaked JWT access tokens or Authorization header values',
                      sev: 'critical',
                    },
                    {
                      label: 'Hardcoded API Keys & Secrets',
                      pattern: '(?i)(api[_-]?key|secret[_-]?token|access[_-]?token)\\s*[:=]\\s*[\'"][a-zA-Z0-9_\\-]{16,}[\'"]',
                      desc: 'Detects exposed API tokens, access credentials, and secret strings',
                      sev: 'critical',
                    },
                    {
                      label: 'US Social Security Number (SSN)',
                      pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
                      desc: 'Matches standard 9-digit US SSN format with hyphens',
                      sev: 'critical',
                    },
                    {
                      label: 'Plaintext Password Assignments',
                      pattern: 'password\\s*[:=]\\s*\\S+',
                      desc: 'Detects passwords written directly in document text or metadata',
                      sev: 'critical',
                    },
                    {
                      label: 'AWS Access Key ID',
                      pattern: '\\bAKIA[0-9A-Z]{16}\\b',
                      desc: 'Matches standard AWS 20-character cloud credential keys',
                      sev: 'critical',
                    },
                    {
                      label: 'Private SSH / RSA Keys',
                      pattern: '-----BEGIN (?:RSA )?PRIVATE KEY-----',
                      desc: 'Matches embedded cryptographic private key headers',
                      sev: 'critical',
                    },
                    {
                      label: 'Confidential Disclaimers',
                      pattern: '(?i)\\b(confidential|strictly\\s+private|do\\s+not\\s+distribute)\\b',
                      desc: 'Detects classified or confidential corporate labels',
                      sev: 'high',
                    },
                  ].map((ex) => (
                    <div
                      key={ex.label}
                      className="p-3 border border-slate-200 bg-slate-50/70 rounded-xl flex items-center justify-between gap-3"
                    >
                      <div className="space-y-0.5">
                        <div className="font-bold text-slate-900">{ex.label}</div>
                        <div className="font-mono text-indigo-700 text-[11px] select-all">{ex.pattern}</div>
                        <div className="text-[11px] text-slate-500">{ex.desc}</div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setEditingWarningId(null);
                          setWarnPattern(ex.pattern);
                          setWarnIsRegex(true);
                          setWarnSeverity(ex.sev as any);
                          setWarnDesc(ex.desc);
                          setShowRegexHelpModal(false);
                          setShowWarningModal(true);
                        }}
                        className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-semibold text-xs whitespace-nowrap shadow-sm transition-all"
                      >
                        Use Pattern →
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Pinned Modal Footer */}
            <div className="px-6 py-3.5 bg-slate-50 border-t border-slate-100 flex items-center justify-between shrink-0 rounded-b-3xl">
              <span className="text-[11px] text-slate-500">
                Press <kbd className="px-1.5 py-0.5 bg-white border border-slate-200 rounded text-slate-600 font-mono text-[10px]">ESC</kbd> or click outside to dismiss
              </span>
              <button
                type="button"
                onClick={() => setShowRegexHelpModal(false)}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-700 text-xs font-semibold rounded-xl transition-colors"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* MODAL: Custom Hex Pattern Editor (Create & Edit) */}
      {showPatternModal && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowPatternModal(false);
          }}
        >
          <div
            className="bg-white border border-slate-200 rounded-3xl max-w-lg w-full shadow-2xl animate-modal-fade flex flex-col max-h-[90vh] overflow-hidden my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-slate-900">
                    {editingPatternId ? '✏️ Edit Custom Pattern Rule' : '➕ Add Hex / Forensic Pattern Rule'}
                  </h3>
                  <button
                    type="button"
                    onClick={() => setShowPatternHelpModal(true)}
                    className="w-5 h-5 rounded-full bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 flex items-center justify-center text-xs font-bold transition-colors cursor-pointer shadow-2xs"
                    title="Pattern creation guide & examples"
                  >
                    ?
                  </button>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Target Format: <span className="font-semibold text-slate-700">{fileFormats.find(f => f.id === patternFormat)?.name || patternFormat.toUpperCase()}</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowPatternModal(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xl font-bold transition-colors cursor-pointer"
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <form onSubmit={handleSaveCustomPattern} className="p-6 space-y-4 overflow-y-auto">
              {patternError && (
                <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 rounded-xl text-xs font-semibold">
                  {patternError}
                </div>
              )}

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Pattern Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. DOS Header Magic / ELF Section"
                  value={patternName}
                  onChange={(e) => setPatternName(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                    Structure Type
                  </label>
                  <select
                    value={patternStructureType}
                    onChange={(e) => setPatternStructureType(e.target.value as StructureType)}
                    className="w-full px-3.5 py-2 border border-slate-300 rounded-xl text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="header">File Header / Magic</option>
                    <option value="section">Section / Table</option>
                    <option value="data">Data Body / Stream</option>
                    <option value="metadata">Metadata / Info</option>
                    <option value="directory">Directory / Index</option>
                    <option value="footer">Footer / EOF / Trailer</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                    Pattern Type
                  </label>
                  <select
                    value={patternType}
                    onChange={(e) => setPatternType(e.target.value as any)}
                    className="w-full px-3.5 py-2 border border-slate-300 rounded-xl text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="hex">Hex Byte Sequence</option>
                    <option value="string">String (UTF-8 / ASCII)</option>
                    <option value="regex">Regular Expression</option>
                    <option value="struct_field">Struct Field (Exact Offset &amp; Length)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                    Byte Offset (Optional, e.g. 0x00 or 0x3C)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. 0x00, 0x3C, or 60"
                    value={patternOffset}
                    onChange={(e) => setPatternOffset(e.target.value)}
                    className="w-full font-mono px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                    Byte Length (Optional)
                  </label>
                  <input
                    type="number"
                    min="1"
                    placeholder="e.g. 2, 4, 8, 16"
                    value={patternLength}
                    onChange={(e) => setPatternLength(e.target.value)}
                    className="w-full font-mono px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
              </div>

              {patternType !== 'struct_field' && (
                <div>
                  <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                    Pattern Value
                  </label>
                  <input
                    type="text"
                    required
                    placeholder={
                      patternType === 'hex'
                        ? '4D 5A or 7F 45 4C 46'
                        : patternType === 'regex'
                        ? 'powershell\\s+-enc\\s+[A-Za-z0-9+/=]+'
                        : 'eval(base64_decode'
                    }
                    value={patternVal}
                    onChange={(e) => setPatternVal(e.target.value)}
                    className="w-full font-mono px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Highlighting Color
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="color"
                    value={patternColor}
                    onChange={(e) => setPatternColor(e.target.value)}
                    className="w-9 h-9 p-0.5 rounded-xl border border-slate-300 cursor-pointer shrink-0"
                  />
                  <input
                    type="text"
                    value={patternColor}
                    onChange={(e) => setPatternColor(e.target.value)}
                    className="w-full font-mono text-xs px-2.5 py-2 border border-slate-300 rounded-xl"
                  />
                </div>

                {/* Color Presets */}
                <div className="flex items-center gap-2 flex-wrap mt-2">
                  {[
                    { c: '#10b981', l: 'Emerald' },
                    { c: '#3b82f6', l: 'Blue' },
                    { c: '#8b5cf6', l: 'Purple' },
                    { c: '#06b6d4', l: 'Cyan' },
                    { c: '#f59e0b', l: 'Amber' },
                    { c: '#f43f5e', l: 'Rose' },
                    { c: '#6366f1', l: 'Indigo' },
                    { c: '#ec4899', l: 'Pink' },
                  ].map((p) => (
                    <button
                      key={p.c}
                      type="button"
                      onClick={() => setPatternColor(p.c)}
                      className={`w-6 h-6 rounded-full border-2 transition-transform hover:scale-110 cursor-pointer ${
                        patternColor.toLowerCase() === p.c.toLowerCase() ? 'border-slate-900 scale-110' : 'border-white shadow-xs'
                      }`}
                      style={{ backgroundColor: p.c }}
                      title={p.l}
                    />
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Description &amp; Forensic Tooltip Note
                </label>
                <textarea
                  rows={2}
                  placeholder="Displayed in the hover card inside the Universal Raw & Hex Inspector..."
                  value={patternDesc}
                  onChange={(e) => setPatternDesc(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-xl text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="pt-3 border-t border-slate-100 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowPatternModal(false)}
                  className="px-4 py-2 border border-slate-300 text-slate-700 hover:bg-slate-100 rounded-xl text-xs font-semibold transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSavingPattern}
                  className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold shadow-sm transition-all cursor-pointer"
                >
                  {isSavingPattern ? 'Saving...' : editingPatternId ? 'Save Changes' : 'Create Pattern'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* MODAL: File Format Definition Editor (Create & Edit) */}
      {showFormatModal && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowFormatModal(false);
          }}
        >
          <div
            className="bg-white border border-slate-200 rounded-3xl max-w-lg w-full shadow-2xl animate-modal-fade flex flex-col max-h-[90vh] overflow-hidden my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  {editingFormatId ? '✏️ Edit File Format Definition' : '➕ Add Supported File Format'}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Configure format headline name, default extension, and magic byte sequences.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowFormatModal(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xl font-bold transition-colors cursor-pointer"
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <form onSubmit={handleSaveFileFormat} className="p-6 space-y-4 overflow-y-auto">
              {formatError && (
                <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 rounded-xl text-xs font-semibold">
                  {formatError}
                </div>
              )}

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Format Headline Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Apple Disk Image (DMG) or WebP Container"
                  value={formatName}
                  onChange={(e) => setFormatName(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              {/* File Extensions (Multi-row) */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                    File Extensions ({formatExtensions.length})
                  </label>
                  <button
                    type="button"
                    onClick={() => setFormatExtensions((prev) => [...prev, ''])}
                    className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                  >
                    ➕ Add Extension
                  </button>
                </div>
                <div className="space-y-2">
                  {formatExtensions.map((ext, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <input
                        type="text"
                        required={idx === 0}
                        placeholder={idx === 0 ? "Primary extension (e.g. .exe)" : "Alternative extension (e.g. .dll)"}
                        value={ext}
                        onChange={(e) => {
                          const val = e.target.value;
                          setFormatExtensions((prev) => prev.map((item, i) => (i === idx ? val : item)));
                        }}
                        className="flex-1 font-mono px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                      />
                      {formatExtensions.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setFormatExtensions((prev) => prev.filter((_, i) => i !== idx))}
                          className="px-2.5 py-2 text-rose-600 hover:bg-rose-50 rounded-xl text-xs font-bold transition-colors cursor-pointer"
                          title="Remove extension"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Magic Byte Signatures (Multi-row) */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                    Magic Byte Signatures ({formatMagicSignatures.length})
                  </label>
                  <button
                    type="button"
                    onClick={() => setFormatMagicSignatures((prev) => [...prev, ''])}
                    className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 transition-colors cursor-pointer"
                  >
                    ➕ Add Signature
                  </button>
                </div>
                <div className="space-y-2">
                  {formatMagicSignatures.map((magic, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="e.g. 4D 5A or 50 4B 03 04 (hex format)"
                        value={magic}
                        onChange={(e) => {
                          const val = e.target.value;
                          setFormatMagicSignatures((prev) => prev.map((item, i) => (i === idx ? val : item)));
                        }}
                        className="flex-1 font-mono px-3.5 py-2 border border-slate-300 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 uppercase"
                      />
                      {formatMagicSignatures.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setFormatMagicSignatures((prev) => prev.filter((_, i) => i !== idx))}
                          className="px-2.5 py-2 text-rose-600 hover:bg-rose-50 rounded-xl text-xs font-bold transition-colors cursor-pointer"
                          title="Remove signature"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                  Format Description
                </label>
                <textarea
                  rows={3}
                  placeholder="Technical summary of this file specification..."
                  value={formatDesc}
                  onChange={(e) => setFormatDesc(e.target.value)}
                  className="w-full px-3.5 py-2 border border-slate-300 rounded-xl text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="pt-3 border-t border-slate-100 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowFormatModal(false)}
                  className="px-4 py-2 border border-slate-300 text-slate-700 hover:bg-slate-100 rounded-xl text-xs font-semibold transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSavingFormat}
                  className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold shadow-sm transition-all cursor-pointer"
                >
                  {isSavingFormat ? 'Saving...' : editingFormatId ? 'Save Changes' : 'Create Format'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* MODAL: Pattern Creation Guide & Help (with Examples) */}
      {showPatternHelpModal && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowPatternHelpModal(false);
          }}
        >
          <div
            className="bg-white border border-slate-200 rounded-3xl max-w-2xl w-full shadow-2xl animate-modal-fade flex flex-col max-h-[90vh] overflow-hidden my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 text-lg font-bold">
                  🎯
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    Forensic Pattern Creation Guide
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Structure classifications, syntax rules, and ready-to-use template examples.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowPatternHelpModal(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 text-xl font-bold transition-colors cursor-pointer"
                aria-label="Close"
              >
                ×
              </button>
            </div>

            {/* Scrollable Content */}
            <div className="p-6 space-y-5 overflow-y-auto text-xs leading-relaxed text-slate-700">
              {/* Section 1: Structure Categories */}
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <span>🧱</span> 1. Forensic Structure Types
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded-xl border border-emerald-200 bg-emerald-50/60">
                    <span className="font-bold text-emerald-800 block mb-0.5">File Header / Magic</span>
                    <span className="text-emerald-700 text-[11px]">Identifies file start signature or magic bytes at offset 0x00 (e.g. 4D 5A, %PDF, 7F 45 4C 46).</span>
                  </div>
                  <div className="p-2.5 rounded-xl border border-blue-200 bg-blue-50/60">
                    <span className="font-bold text-blue-800 block mb-0.5">Section / Table</span>
                    <span className="text-blue-700 text-[11px]">Section headers, program headers, partition tables, segment descriptors.</span>
                  </div>
                  <div className="p-2.5 rounded-xl border border-purple-200 bg-purple-50/60">
                    <span className="font-bold text-purple-800 block mb-0.5">Data Body / Stream</span>
                    <span className="text-purple-700 text-[11px]">Compressed payload, script code, macro streams, raw bytecode or bitmap scanlines.</span>
                  </div>
                  <div className="p-2.5 rounded-xl border border-amber-200 bg-amber-50/60">
                    <span className="font-bold text-amber-800 block mb-0.5">Metadata / Info</span>
                    <span className="text-amber-700 text-[11px]">Author info, compile timestamps, comments, version resources, document properties.</span>
                  </div>
                  <div className="p-2.5 rounded-xl border border-sky-200 bg-sky-50/60">
                    <span className="font-bold text-sky-800 block mb-0.5">Directory / Index</span>
                    <span className="text-sky-700 text-[11px]">Central directories, cross-reference tables (XREF), symbol export/import tables.</span>
                  </div>
                  <div className="p-2.5 rounded-xl border border-rose-200 bg-rose-50/60">
                    <span className="font-bold text-rose-800 block mb-0.5">Footer / EOF / Trailer</span>
                    <span className="text-rose-700 text-[11px]">End of file markers, trailer dictionaries, digital signature footers (e.g. 50 4B 05 06, %%EOF).</span>
                  </div>
                </div>
              </div>

              {/* Section 2: Pattern Match Types */}
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <span>⚙️</span> 2. Pattern Match Types &amp; Syntax
                </h4>
                <div className="space-y-2 font-mono text-[11px]">
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="font-bold text-slate-900 font-sans mb-0.5">Hex Byte Sequence</div>
                    <div className="text-indigo-600">e.g. 4D 5A or 7F 45 4C 46 or FF D8 FF E0</div>
                    <div className="text-slate-500 font-sans mt-0.5 text-[11px]">Matches exact hex byte sequence. If Offset is set (e.g. 0x00), only matches at that exact byte offset.</div>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="font-bold text-slate-900 font-sans mb-0.5">String (UTF-8 / ASCII)</div>
                    <div className="text-indigo-600">e.g. powershell or eval( or /JavaScript or %PDF</div>
                    <div className="text-slate-500 font-sans mt-0.5 text-[11px]">Matches plain ASCII or UTF-8 string across the file or at an optional exact offset.</div>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="font-bold text-slate-900 font-sans mb-0.5">Regular Expression</div>
                    <div className="text-indigo-600">e.g. powershell\s+-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]+</div>
                    <div className="text-slate-500 font-sans mt-0.5 text-[11px]">Standard regex syntax matching strings with variable patterns across text streams.</div>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="font-bold text-slate-900 font-sans mb-0.5">Struct Field (Exact Offset &amp; Length)</div>
                    <div className="text-indigo-600">Offset: 0x3C, Length: 4 (e_lfanew in PE DOS Header)</div>
                    <div className="text-slate-500 font-sans mt-0.5 text-[11px]">Highlights a specific binary field by fixed byte offset and byte length, regardless of its content.</div>
                  </div>
                </div>
              </div>

              {/* Section 3: Template Examples */}
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <span>💡</span> 3. Common Template Examples
                </h4>
                <div className="space-y-2">
                  {[
                    {
                      name: 'PE DOS Header Magic (MZ)',
                      type: 'hex',
                      val: '4D 5A',
                      offset: '0x00',
                      len: '2',
                      st: 'header',
                      color: '#10b981',
                      desc: 'Marks the start of Microsoft MS-DOS and PE executable binaries.',
                    },
                    {
                      name: 'PE e_lfanew Pointer',
                      type: 'struct_field',
                      val: '',
                      offset: '0x3C',
                      len: '4',
                      st: 'header',
                      color: '#06b6d4',
                      desc: '4-byte file pointer to the PE NT Headers signature block.',
                    },
                    {
                      name: 'ELF Magic Header',
                      type: 'hex',
                      val: '7F 45 4C 46',
                      offset: '0x00',
                      len: '4',
                      st: 'header',
                      color: '#10b981',
                      desc: 'Magic bytes 0x7F ELF identifying standard Linux/Unix binary.',
                    },
                    {
                      name: 'PDF Magic Header',
                      type: 'hex',
                      val: '25 50 44 46',
                      offset: '0x00',
                      len: '4',
                      st: 'header',
                      color: '#10b981',
                      desc: 'Header magic %PDF indicating Adobe Portable Document Format.',
                    },
                    {
                      name: 'ZIP End of Central Directory',
                      type: 'hex',
                      val: '50 4B 05 06',
                      offset: '',
                      len: '4',
                      st: 'footer',
                      color: '#f43f5e',
                      desc: 'PK 0x05 0x06 signature denoting End of Central Directory record in ZIP.',
                    },
                    {
                      name: 'JPEG Start of Image (SOI)',
                      type: 'hex',
                      val: 'FF D8 FF',
                      offset: '0x00',
                      len: '3',
                      st: 'header',
                      color: '#10b981',
                      desc: 'Start of Image marker at beginning of all JPEG files.',
                    },
                  ].map((ex) => (
                    <div
                      key={ex.name}
                      className="p-3 border border-slate-200 bg-slate-50/70 rounded-xl flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="space-y-0.5 min-w-0">
                        <div className="flex items-center gap-2">
                          <span
                            className="w-2.5 h-2.5 rounded-full shrink-0"
                            style={{ backgroundColor: ex.color }}
                          />
                          <span className="font-bold text-slate-900">{ex.name}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 bg-slate-200 text-slate-700 rounded">
                            {ex.type}
                          </span>
                        </div>
                        <div className="font-mono text-indigo-700 text-[11px]">
                          {ex.val ? `Pattern: ${ex.val}` : `Offset: ${ex.offset}, Len: ${ex.len}B`}
                        </div>
                        <div className="text-[11px] text-slate-500">{ex.desc}</div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setPatternName(ex.name);
                          setPatternType(ex.type as any);
                          setPatternVal(ex.val);
                          setPatternOffset(ex.offset);
                          setPatternLength(ex.len);
                          setPatternStructureType(ex.st as StructureType);
                          setPatternColor(ex.color);
                          setPatternDesc(ex.desc);
                          setShowPatternHelpModal(false);
                        }}
                        className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-semibold text-xs whitespace-nowrap shadow-sm transition-all cursor-pointer shrink-0"
                      >
                        Use Template →
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-3.5 bg-slate-50 border-t border-slate-100 flex items-center justify-between shrink-0">
              <span className="text-[11px] text-slate-500">
                Press <kbd className="px-1.5 py-0.5 bg-white border border-slate-200 rounded text-slate-600 font-mono text-[10px]">ESC</kbd> or click outside to dismiss
              </span>
              <button
                type="button"
                onClick={() => setShowPatternHelpModal(false)}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>,
        document.body
      )}

      {showUpdateModalFromSettings && updateModalInfo && (
        <NewVersionModal
          isOpen={showUpdateModalFromSettings}
          onClose={() => setShowUpdateModalFromSettings(false)}
          updateInfo={updateModalInfo}
          onDisableFutureChecks={() => {
            handleToggleCheckForUpdates(false);
            setShowUpdateModalFromSettings(false);
          }}
        />
      )}
    </div>
  );
};
