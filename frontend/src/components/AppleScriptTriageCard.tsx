import React, { useState } from 'react';
import { AppleScriptTriageInfo } from '../types';
import {
  Terminal,
  ShieldAlert,
  ShieldCheck,
  Code,
  Layers,
  Globe,
  Copy,
  Check,
  FileCode,
  Cpu,
  Lock,
  ExternalLink,
  AlertTriangle
} from 'lucide-react';

interface AppleScriptTriageCardProps {
  applescriptInfo: AppleScriptTriageInfo;
}

export const AppleScriptTriageCard: React.FC<AppleScriptTriageCardProps> = ({ applescriptInfo }) => {
  const [activeTab, setActiveTab] = useState<'findings' | 'source' | 'apps' | 'commands'>('findings');
  const [copied, setCopied] = useState(false);

  const {
    format = 'AppleScript / OSA',
    decompilation_method = 'Source Text',
    extracted_text_preview = '',
    script_source = '',
    line_count = 0,
    statement_count = 0,
    risk_score = 0,
    risk_level = 'LOW RISK',
    findings = [],
    capabilities = {},
    targeted_applications = [],
    embedded_shell_commands = [],
    phishing_dialogs = [],
    iocs = { urls: [], ips: [], commands: [], file_paths: [] },
    summary = ''
  } = applescriptInfo || {};

  const fullSource = script_source || extracted_text_preview || '';

  const handleCopySource = () => {
    if (!fullSource) return;
    navigator.clipboard.writeText(fullSource);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'HIGH':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      default:
        return 'bg-blue-50 text-blue-700 border-blue-200';
    }
  };

  const activeCapabilityCategories = Object.entries(capabilities).filter(([_, v]) => Array.isArray(v) && v.length > 0);

  return (
    <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden mb-6">
      {/* Header */}
      <div className="px-6 py-5 bg-gradient-to-r from-sky-50/90 via-indigo-50/40 to-white border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 bg-sky-600 text-white rounded-xl shadow-xs">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base font-bold text-slate-900">
                AppleScript &amp; macOS OSA Security Analysis
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-bold bg-sky-100/80 text-sky-800 border border-sky-200">
                {format}
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded-md font-mono bg-slate-100 text-slate-700 border border-slate-200">
                {decompilation_method}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              macOS Open Scripting Architecture threat behaviors, privilege escalation, synthetic input, and dialog harvesting
            </p>
          </div>
        </div>

        {/* Risk Badge & Metrics */}
        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="text-[11px] text-slate-500 font-medium block">Risk Score</span>
            <span className="text-base font-extrabold text-slate-900 font-mono">{risk_score}/100</span>
          </div>
          <span className={`inline-flex items-center px-3.5 py-1.5 rounded-full text-xs font-bold border shadow-xs ${
            risk_level === 'CRITICAL' ? 'bg-red-100 text-red-800 border-red-300' :
            risk_level === 'HIGH RISK' ? 'bg-orange-100 text-orange-800 border-orange-300' :
            risk_level === 'MEDIUM RISK' ? 'bg-amber-100 text-amber-800 border-amber-300' :
            'bg-emerald-100 text-emerald-800 border-emerald-200'
          }`}>
            {risk_level === 'CLEAN' ? (
              <ShieldCheck className="w-4 h-4 mr-1.5 text-emerald-600" />
            ) : (
              <ShieldAlert className="w-4 h-4 mr-1.5" />
            )}
            {risk_level}
          </span>
        </div>
      </div>

      {/* Forensic Summary */}
      {summary && (
        <div className="px-6 py-3 bg-slate-50/80 border-b border-slate-200 text-xs text-slate-700 flex items-start gap-2">
          <span className="font-bold text-slate-900 shrink-0">Summary:</span>
          <span>{summary}</span>
        </div>
      )}

      {/* Statistical KPIs Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-slate-100 border-b border-slate-200 bg-white">
        <div className="px-6 py-3">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Threat Findings</span>
          <span className="text-lg font-bold text-slate-900 font-mono">{findings.length}</span>
        </div>
        <div className="px-6 py-3">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Targeted Apps</span>
          <span className="text-lg font-bold text-indigo-600 font-mono">{targeted_applications.length}</span>
        </div>
        <div className="px-6 py-3">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Shell Commands</span>
          <span className="text-lg font-bold text-amber-600 font-mono">{embedded_shell_commands.length}</span>
        </div>
        <div className="px-6 py-3">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Script Lines</span>
          <span className="text-lg font-bold text-slate-900 font-mono">
            {line_count || fullSource.split('\n').length}
            {statement_count > 0 && <span className="text-xs text-slate-500 font-normal ml-1.5">({statement_count} stmts)</span>}
          </span>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="px-6 pt-3 bg-white border-b border-slate-200 flex items-center space-x-1 overflow-x-auto">
        <button
          type="button"
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeTab === 'findings'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Threat Behaviors &amp; Capabilities ({findings.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('source')}
          className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeTab === 'source'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Code className="w-4 h-4" />
          <span>Decompiled Script Source</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('apps')}
          className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeTab === 'apps'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Targeted macOS Apps ({targeted_applications.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('commands')}
          className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
            activeTab === 'commands'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span>Shell Commands &amp; IOCs ({embedded_shell_commands.length + (iocs.urls?.length || 0)})</span>
        </button>
      </div>

      {/* Tab Panels */}
      <div className="p-6">
        {/* TAB 1: FINDINGS & CAPABILITIES */}
        {activeTab === 'findings' && (
          <div className="space-y-6">
            {/* Operational Capabilities Grid */}
            {activeCapabilityCategories.length > 0 && (
              <div>
                <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-indigo-600" />
                  <span>Categorized Operational Capabilities ({activeCapabilityCategories.length})</span>
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {activeCapabilityCategories.map(([catKey, items]) => (
                    <div key={catKey} className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/60 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-800 text-xs capitalize flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-indigo-500" />
                          {catKey.replace(/_/g, ' ')}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-white border border-slate-200 font-bold font-mono text-slate-700">
                          {items.length} match{items.length > 1 ? 'es' : ''}
                        </span>
                      </div>
                      <div className="space-y-1 pt-1">
                        {items.slice(0, 3).map((it: any, idx: number) => (
                          <div key={idx} className="text-[11px] text-slate-600 font-mono bg-white p-1.5 rounded border border-slate-200/80 truncate">
                            {it.snippet || it.title}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed Findings List */}
            <div>
              <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-3">
                Detailed Threat Behavior Indicators ({findings.length})
              </h4>
              {findings && findings.length > 0 ? (
                <div className="space-y-3">
                  {findings.map((f, i) => (
                    <div key={i} className={`p-4 rounded-xl border transition-all ${
                      f.severity === 'CRITICAL' ? 'bg-red-50/50 border-red-200' :
                      f.severity === 'HIGH' ? 'bg-orange-50/50 border-orange-200' :
                      'bg-amber-50/50 border-amber-200'
                    }`}>
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wider ${getSeverityBadge(f.severity)}`}>
                            {f.severity}
                          </span>
                          <span className="font-bold text-slate-900 text-xs">
                            {f.title}
                          </span>
                          {f.count > 1 && (
                            <span className="text-[10px] font-mono text-slate-500">
                              ({f.count}x occurrences)
                            </span>
                          )}
                        </div>
                        {f.mitre && (
                          <span className="font-mono text-[10px] font-bold text-indigo-700 bg-white px-2 py-0.5 rounded border border-indigo-200 shadow-2xs">
                            MITRE {f.mitre}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-700 mb-2 leading-relaxed">
                        {f.description}
                      </p>
                      {f.snippet && (
                        <div className="p-2.5 bg-slate-900 text-emerald-400 rounded-lg font-mono text-[11px] overflow-x-auto shadow-inner">
                          <code>{f.snippet}</code>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-8 text-center text-slate-400 bg-slate-50 rounded-xl border border-slate-200">
                  <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-500" />
                  <span className="text-xs font-medium">No malicious AppleScript behaviors identified.</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: DECOMPILED SCRIPT SOURCE */}
        {activeTab === 'source' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs text-slate-600">
                <span className="font-bold text-slate-800">Decompilation Output: </span>
                <span>{decompilation_method} ({line_count || fullSource.split('\n').length} lines)</span>
              </div>
              <button
                type="button"
                onClick={handleCopySource}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Script'}</span>
              </button>
            </div>

            <div className="border border-slate-200 rounded-xl overflow-hidden bg-slate-950 font-mono text-xs">
              <div className="flex max-h-[500px] overflow-y-auto divide-x divide-slate-800">
                {/* Line Numbers */}
                <div className="bg-slate-900 text-slate-500 py-3 px-3 select-none text-right font-mono min-w-[50px] space-y-0.5">
                  {fullSource.split('\n').map((_, i) => (
                    <div key={i} className="text-[11px] leading-5 text-slate-600">
                      {i + 1}
                    </div>
                  ))}
                </div>
                {/* Code Content */}
                <div className="p-3 text-slate-200 overflow-x-auto flex-1 font-mono space-y-0.5">
                  {fullSource.split('\n').map((line, i) => {
                    const isDangerous =
                      line.includes('with administrator privileges') ||
                      line.includes('with hidden answer') ||
                      line.includes('keystroke') ||
                      line.includes('curl ') ||
                      line.includes('nc -e');
                    return (
                      <div
                        key={i}
                        className={`text-[11px] leading-5 whitespace-pre px-1 rounded ${
                          isDangerous
                            ? 'bg-rose-950/70 text-rose-300 font-semibold'
                            : 'hover:bg-slate-900'
                        }`}
                      >
                        {line || ' '}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: TARGETED MACOS APPLICATIONS */}
        {activeTab === 'apps' && (
          <div className="space-y-4">
            <div className="text-xs text-slate-600">
              AppleScript leverages AppleEvents to automate and compromise other applications on macOS.
              Below are all targets referenced via <code className="bg-slate-100 px-1 py-0.5 rounded text-indigo-700 font-mono">tell application &quot;...&quot;</code>:
            </div>

            {targeted_applications && targeted_applications.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {targeted_applications.map((app, idx) => (
                  <div key={idx} className="p-4 rounded-xl border border-slate-200 bg-white hover:border-slate-300 transition-all shadow-xs space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className="p-1.5 bg-indigo-50 text-indigo-700 rounded-lg">
                          <Layers className="w-4 h-4" />
                        </div>
                        <span className="font-bold text-slate-900 text-sm">{app.name}</span>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${getSeverityBadge(app.risk)}`}>
                        {app.risk} RISK
                      </span>
                    </div>

                    <div className="text-xs text-slate-700 font-medium">
                      {app.reason}
                    </div>

                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      {app.description}
                    </p>

                    <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                      <span>TCC: <strong className="text-slate-700">{app.tcc_permission}</strong></span>
                      <span>References: {app.occurrences}x</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400 bg-slate-50 rounded-xl border border-slate-200">
                <FileCode className="w-8 h-8 mx-auto mb-2 text-slate-400" />
                <span className="text-xs font-medium">No external macOS applications targeted in this script.</span>
              </div>
            )}
          </div>
        )}

        {/* TAB 4: SHELL COMMANDS & NETWORK IOCS */}
        {activeTab === 'commands' && (
          <div className="space-y-6">
            {/* Embedded Shell Commands */}
            <div>
              <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-2.5 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-amber-600" />
                <span>Extracted Unix Shell Commands ({embedded_shell_commands.length})</span>
              </h4>
              {embedded_shell_commands && embedded_shell_commands.length > 0 ? (
                <div className="space-y-2.5">
                  {embedded_shell_commands.map((cmd, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] font-mono font-semibold text-slate-500">
                          Context: <strong className="text-slate-800">{cmd.context}</strong>
                        </span>
                        {cmd.is_dangerous && (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-200 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            <span>Dangerous Shell Payload</span>
                          </span>
                        )}
                      </div>
                      <pre className="p-2.5 bg-slate-950 text-emerald-400 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                        <code>{cmd.command}</code>
                      </pre>
                      {cmd.indicators && cmd.indicators.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {cmd.indicators.map((ind, i) => (
                            <span key={i} className="text-[10px] font-medium bg-amber-50 text-amber-800 border border-amber-200 px-2 py-0.5 rounded-md">
                              {ind}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400 bg-slate-50 p-4 rounded-xl border border-slate-200">
                  No lower-level Unix shell commands executed via <code className="font-mono">do shell script</code>.
                </p>
              )}
            </div>

            {/* Phishing / Authentication Dialogs */}
            {phishing_dialogs && phishing_dialogs.length > 0 && (
              <div>
                <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-2.5 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-rose-600" />
                  <span>Harvested Phishing Dialogs ({phishing_dialogs.length})</span>
                </h4>
                <div className="space-y-2">
                  {phishing_dialogs.map((d, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl border border-rose-200 bg-rose-50/40 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-rose-900 text-xs">
                          {d.is_phishing ? 'Spoofed Authentication Dialog' : 'User Prompt'}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white border border-rose-200 text-rose-800 font-bold">
                          {d.has_hidden_answer ? 'HIDDEN ANSWER (PASSWORD)' : 'CLEARTEXT'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-800 italic bg-white p-2 rounded border border-rose-100">
                        &quot;{d.prompt}&quot;
                      </p>
                      {d.buttons && d.buttons.length > 0 && (
                        <div className="text-[11px] text-slate-500">
                          Buttons: <strong className="text-slate-700">{d.buttons.join(', ')}</strong>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Network IOCs & Extracted URLs */}
            <div>
              <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-2.5 flex items-center gap-2">
                <Globe className="w-4 h-4 text-sky-600" />
                <span>Extracted Network IOCs &amp; Remote URLs ({iocs.urls?.length || 0})</span>
              </h4>
              {iocs.urls && iocs.urls.length > 0 ? (
                <ul className="space-y-1.5 font-mono text-xs">
                  {iocs.urls.map((u, i) => (
                    <li key={i} className="p-2 bg-slate-50 rounded-lg border border-slate-200 flex items-center justify-between gap-2">
                      <span className="text-indigo-600 font-semibold break-all">{u}</span>
                      <a
                        href={u}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-slate-400 hover:text-slate-700 shrink-0"
                        title="Open external link"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-400 bg-slate-50 p-4 rounded-xl border border-slate-200">
                  No remote network URLs extracted from AppleScript strings.
                </p>
              )}
            </div>

            {/* Target File Paths */}
            {iocs.file_paths && iocs.file_paths.length > 0 && (
              <div>
                <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-2 flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-slate-600" />
                  <span>Targeted Local File Paths ({iocs.file_paths.length})</span>
                </h4>
                <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                  {iocs.file_paths.map((p, i) => (
                    <span key={i} className="bg-slate-100 text-slate-800 px-2 py-1 rounded border border-slate-200">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
