import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  Copy,
  Check,
  Terminal,
  FileCode,
  Download,
  AlertCircle,
  Layers,
  Cpu,
  Database
} from 'lucide-react';
import { DetectionRules } from '../types';
import { apiClient } from '../api/client';

export type KqlType =
  | 'mde_process_creation'
  | 'windows_event_4688'
  | 'mde_file_events'
  | 'mde_network_c2'
  | 'email_gateway'
  | 'sentinel_analytics_rule';

interface DetectionRulesModalProps {
  isOpen: boolean;
  onClose: () => void;
  jobId: string;
  filename?: string;
  initialRules?: DetectionRules | null;
}

export const DetectionRulesModal: React.FC<DetectionRulesModalProps> = ({
  isOpen,
  onClose,
  jobId,
  filename = 'artifact',
  initialRules
}) => {
  const [rules, setRules] = useState<DetectionRules | null>(initialRules || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeMainTab, setActiveMainTab] = useState<'sentinel' | 'yara'>('sentinel');
  const [activeKqlType, setActiveKqlType] = useState<KqlType>('mde_process_creation');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && !rules && jobId) {
      setLoading(true);
      setError(null);
      apiClient.getJobDetectionRules(jobId)
        .then(res => {
          setRules(res);
          setLoading(false);
        })
        .catch(err => {
          setError(err.message || 'Failed to generate detection rules');
          setLoading(false);
        });
    } else if (isOpen && initialRules) {
      setRules(initialRules);
    }
  }, [isOpen, jobId, initialRules]);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const downloadYaraRule = () => {
    if (!rules?.yara_rule) return;
    const blob = new Blob([rules.yara_rule], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Detect_${filename.replace(/[^a-zA-Z0-9_]/g, '_')}.yar`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const kqlDescriptions: Record<KqlType, { label: string; desc: string; icon: any }> = {
    mde_process_creation: {
      label: 'MDE Process Execution',
      desc: 'Hunts across Microsoft Defender for Endpoint DeviceProcessEvents table using SHA256, MD5, and command lines.',
      icon: Terminal
    },
    windows_event_4688: {
      label: 'SecurityEvent 4688',
      desc: 'Queries Windows Security Log Event ID 4688 (Process Creation with Command Line Auditing enabled).',
      icon: Shield
    },
    mde_file_events: {
      label: 'DeviceFileEvents',
      desc: 'Monitors file creation, renaming, and modification across endpoints via MDE DeviceFileEvents.',
      icon: FileCode
    },
    mde_network_c2: {
      label: 'Outbound C2 / Beaconing',
      desc: 'Matches outbound network flows to identified remote C2 IP addresses and suspicious domains.',
      icon: Database
    },
    email_gateway: {
      label: 'M365 Email Gateway',
      desc: 'Correlates Exchange Online Inbound EmailEvents with EmailAttachmentInfo matching hash and filename.',
      icon: Layers
    },
    sentinel_analytics_rule: {
      label: 'Scheduled Analytics Alert Rule',
      desc: 'Production SIEM Analytics Rule template featuring custom entity mapping (Host, Account, FileHash) for incident graphs.',
      icon: Cpu
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
      <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-5xl w-full max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-2xl">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-900">
                  Automated Threat Detection Rules
                </h3>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                  Sentinel KQL &amp; YARA
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Synthesized directly from forensic indicators, hashes, and behavioral patterns discovered in <span className="font-semibold text-slate-700">{filename}</span>.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Indicators Summary Strip */}
        {rules?.indicators_used && (
          <div className="px-6 py-2.5 bg-slate-100/70 border-b border-slate-200 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs font-mono text-slate-600">
            <span className="text-[10px] font-sans font-bold uppercase text-slate-400">Indicators:</span>
            {rules.indicators_used.sha256 && (
              <span className="text-slate-800">
                SHA256: <strong className="font-mono text-indigo-700">{rules.indicators_used.sha256.substring(0, 10)}...</strong>
              </span>
            )}
            {rules.indicators_used.imphash && (
              <span className="text-slate-800">
                Imphash: <strong className="font-mono">{rules.indicators_used.imphash.substring(0, 8)}...</strong>
              </span>
            )}
            {rules.indicators_used.rich_header_hash && (
              <span className="text-slate-800">
                Rich Hash: <strong className="font-mono text-indigo-700">{rules.indicators_used.rich_header_hash.substring(0, 8)}...</strong>
              </span>
            )}
            {rules.indicators_used.ips.length > 0 && (
              <span className="text-slate-800">
                C2 IPs: <strong>{rules.indicators_used.ips.length}</strong>
              </span>
            )}
            {rules.indicators_used.domains.length > 0 && (
              <span className="text-slate-800">
                Domains: <strong>{rules.indicators_used.domains.length}</strong>
              </span>
            )}
            {rules.indicators_used.mitre_techniques.length > 0 && (
              <span className="text-slate-800">
                ATT&amp;CK: <strong>{rules.indicators_used.mitre_techniques.slice(0, 3).join(', ')}</strong>
              </span>
            )}
          </div>
        )}

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {loading && (
            <div className="py-20 text-center space-y-3">
              <div className="w-8 h-8 border-3 border-indigo-600 border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-sm font-semibold text-slate-700">Synthesizing detection queries from forensic findings...</p>
            </div>
          )}

          {error && (
            <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl text-xs text-rose-800 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!loading && rules && (
            <>
              {/* Primary Format Tabs: Sentinel KQL vs YARA */}
              <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
                <button
                  onClick={() => setActiveMainTab('sentinel')}
                  className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                    activeMainTab === 'sentinel'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  <Terminal className="w-4 h-4" />
                  <span>Microsoft Sentinel (KQL)</span>
                </button>

                <button
                  onClick={() => setActiveMainTab('yara')}
                  className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 cursor-pointer ${
                    activeMainTab === 'yara'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  <FileCode className="w-4 h-4" />
                  <span>YARA Signature Rule</span>
                </button>
              </div>

              {/* TAB 1: Microsoft Sentinel (KQL) */}
              {activeMainTab === 'sentinel' && (
                <div className="space-y-4">
                  {/* KQL Query Type Selector Sub-Tabs */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                    {(Object.keys(kqlDescriptions) as KqlType[]).map(typeKey => {
                      const item = kqlDescriptions[typeKey];
                      const Icon = item.icon;
                      const isSelected = activeKqlType === typeKey;
                      return (
                        <button
                          key={typeKey}
                          onClick={() => setActiveKqlType(typeKey)}
                          className={`p-2.5 rounded-xl border text-left text-xs transition-all flex flex-col justify-between cursor-pointer ${
                            isSelected
                              ? 'bg-blue-50/80 border-blue-300 text-blue-900 font-bold shadow-2xs'
                              : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50'
                          }`}
                        >
                          <Icon className={`w-4 h-4 mb-1.5 ${isSelected ? 'text-blue-600' : 'text-slate-400'}`} />
                          <span className="text-[11px] leading-tight line-clamp-2">{item.label}</span>
                        </button>
                      );
                    })}
                  </div>

                  {/* KQL Description Banner */}
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between text-xs">
                    <p className="text-slate-600">
                      {kqlDescriptions[activeKqlType]?.desc}
                    </p>
                    <button
                      onClick={() => copyToClipboard(rules.sentinel_kql[activeKqlType] || '', `kql_${activeKqlType}`)}
                      className="px-3 py-1.5 rounded-lg bg-white border border-slate-300 hover:border-blue-400 text-slate-800 font-semibold text-xs flex items-center gap-1.5 cursor-pointer shadow-2xs ml-4 shrink-0"
                    >
                      {copiedKey === `kql_${activeKqlType}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-600" />}
                      <span>{copiedKey === `kql_${activeKqlType}` ? 'Copied' : 'Copy KQL'}</span>
                    </button>
                  </div>

                  {/* KQL Query Display Code Box */}
                  <div className="relative">
                    <pre className="p-4 bg-slate-900 text-sky-300 rounded-2xl font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[380px] border border-slate-800 select-all">
                      {rules.sentinel_kql[activeKqlType] || '// No query generated for this category'}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 2: YARA Rule */}
              {activeMainTab === 'yara' && (
                <div className="space-y-4">
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-between text-xs">
                    <p className="text-slate-600">
                      Compiled, production-grade YARA rule with guaranteed variable reference integrity, hash metadata, and format header conditions.
                    </p>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={downloadYaraRule}
                        className="px-3 py-1.5 rounded-lg bg-white border border-slate-300 hover:border-indigo-400 text-slate-800 font-semibold text-xs flex items-center gap-1.5 cursor-pointer shadow-2xs"
                      >
                        <Download className="w-3.5 h-3.5 text-slate-600" />
                        <span>Download .yar</span>
                      </button>
                      <button
                        onClick={() => copyToClipboard(rules.yara_rule, 'yara_rule')}
                        className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs flex items-center gap-1.5 cursor-pointer shadow-2xs"
                      >
                        {copiedKey === 'yara_rule' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedKey === 'yara_rule' ? 'Copied' : 'Copy YARA'}</span>
                      </button>
                    </div>
                  </div>

                  {/* YARA Rule Code Box */}
                  <div className="relative">
                    <pre className="p-4 bg-slate-900 text-emerald-400 rounded-2xl font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[420px] border border-slate-800 select-all">
                      {rules.yara_rule}
                    </pre>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50/70 flex items-center justify-between text-xs text-slate-500">
          <span>Targeting Microsoft Sentinel SIEM &amp; YARA v4+ Scanning Engines</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-200 hover:bg-slate-300 text-slate-800 font-semibold cursor-pointer transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
