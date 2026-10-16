import React, { useState } from 'react';
import {
  Globe,
  Radio,
  FolderSearch,
  Folder,
  Terminal,
  EyeOff,
  KeyRound,
  Lock,
  Archive,
  Clock,
  AlertTriangle,
  Bug,
  CheckCircle2,
  FileCode,
  Server,
  Activity,
  Copy,
  Check
} from 'lucide-react';
import {
  JavaBehavioralAnalysis
} from '../types';

interface JavaBehavioralForensicsProps {
  behavioral?: JavaBehavioralAnalysis;
  filename?: string;
  isJar?: boolean;
}

export const JavaBehavioralForensics: React.FC<JavaBehavioralForensicsProps> = ({
  behavioral,
  filename = 'application.jar',
  isJar = true
}) => {
  const [selectedPillar, setSelectedPillar] = useState<'internet' | 'file' | 'command' | 'obfuscation'>('internet');
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  if (!behavioral) {
    return (
      <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-xs">
        No behavioral forensics telemetry available.
      </div>
    );
  }

  const {
    internet_activity,
    file_access,
    command_execution,
    code_obfuscation,
    strrat_heuristics
  } = behavioral;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(id);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict.toUpperCase()) {
      case 'SUSPICIOUS':
      case 'OBFUSCATED':
        return 'bg-rose-100 text-rose-800 border-rose-200';
      case 'POTENTIAL':
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

  const getCapabilityIcon = (id: string) => {
    switch (id) {
      case 'raw_sockets': return <Radio className="w-4 h-4 text-purple-600" />;
      case 'http_requests': return <Globe className="w-4 h-4 text-sky-600" />;
      case 'payload_downloader': return <Activity className="w-4 h-4 text-rose-600" />;
      case 'socks_proxy': return <Server className="w-4 h-4 text-indigo-600" />;
      case 'c2_telemetry_endpoints': return <Radio className="w-4 h-4 text-rose-600" />;
      case 'filesystem_traversal': return <FolderSearch className="w-4 h-4 text-amber-600" />;
      case 'sensitive_folders': return <Folder className="w-4 h-4 text-amber-600" />;
      case 'credential_harvesting': return <KeyRound className="w-4 h-4 text-rose-600" />;
      case 'archive_packaging': return <Archive className="w-4 h-4 text-indigo-600" />;
      case 'ransomware_simulation': return <Lock className="w-4 h-4 text-rose-600" />;
      case 'file_dropper_lockfile': return <FileCode className="w-4 h-4 text-orange-600" />;
      case 'process_spawning': return <Terminal className="w-4 h-4 text-rose-600" />;
      case 'command_shells': return <Terminal className="w-4 h-4 text-rose-600" />;
      case 'system_persistence_admin': return <Clock className="w-4 h-4 text-purple-600" />;
      case 'script_launching': return <FileCode className="w-4 h-4 text-amber-600" />;
      default: return <AlertTriangle className="w-4 h-4 text-slate-600" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. STRRAT Case Study Match Alert Banner */}
      {strrat_heuristics && strrat_heuristics.is_strrat_candidate && (
        <div className="p-5 bg-gradient-to-r from-rose-50 via-purple-50 to-rose-50 border-2 border-rose-300 rounded-3xl shadow-sm space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-rose-600 text-white rounded-xl shadow-sm">
                <Bug className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-bold text-slate-900">
                    SecurityScorecard Case Study Alert: STRRAT Remote Access Trojan Match
                  </h4>
                  <span className={`text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full border ${
                    strrat_heuristics.confidence === 'HIGH' ? 'bg-rose-600 text-white border-rose-700 animate-pulse' : 'bg-orange-100 text-orange-800 border-orange-300'
                  }`}>
                    {strrat_heuristics.confidence} Confidence
                  </span>
                </div>
                <p className="text-xs text-slate-600 mt-0.5">
                  Static bytecode patterns match documented threat signatures from SecurityScorecard's forensic report <em>"How to Analyze Java Malware – A Case Study of STRRAT"</em>.
                </p>
              </div>
            </div>
            <a
              href="https://securityscorecard.com/wp-content/uploads/2024/01/How-to-Analyze-Java-Malware-%E2%80%93-A-Case-Study-of-STRRAT.pdf"
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-semibold text-rose-700 hover:text-rose-900 underline flex items-center gap-1"
            >
              Read Case Study PDF →
            </a>
          </div>

          {/* Matched Hallmarks Checklist */}
          <div className="pt-2 border-t border-rose-200/70">
            <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block mb-2">
              Matched STRRAT Threat Indicators:
            </span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              {strrat_heuristics.matched_indicators.map((ind, i) => (
                <div key={i} className="flex items-start gap-2 p-2 bg-white/80 rounded-xl border border-rose-200 text-slate-800">
                  <CheckCircle2 className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <span className="font-medium">{ind}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 2. Four Pillars Summary Cards */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-900">
              Java Behavioral Forensic Triage (4 Core Pillars)
            </h4>
            <p className="text-xs text-slate-500">
              Evaluates suspicious program capabilities in {filename} according to SecurityScorecard's static analysis methodology.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Pillar 1: Internet Activity */}
          <button
            onClick={() => setSelectedPillar('internet')}
            className={`p-4 rounded-2xl border text-left transition-all cursor-pointer ${
              selectedPillar === 'internet'
                ? 'bg-sky-50/70 border-sky-300 shadow-sm ring-2 ring-sky-400/20'
                : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-sky-600" />
                <span className="text-xs font-bold text-slate-800">🌐 Internet Activity</span>
              </div>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getVerdictBadge(internet_activity.verdict)}`}>
                {internet_activity.verdict}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mb-2 line-clamp-2">
              Can this {isJar ? 'JAR' : 'Java program'} contact external servers?
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-100">
              <span className="font-semibold text-slate-700">{internet_activity.capabilities.length} capabilities</span>
              <span className="font-mono text-[11px] text-slate-500">{internet_activity.score}/100</span>
            </div>
          </button>

          {/* Pillar 2: File Access */}
          <button
            onClick={() => setSelectedPillar('file')}
            className={`p-4 rounded-2xl border text-left transition-all cursor-pointer ${
              selectedPillar === 'file'
                ? 'bg-amber-50/70 border-amber-300 shadow-sm ring-2 ring-amber-400/20'
                : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <FolderSearch className="w-4 h-4 text-amber-600" />
                <span className="text-xs font-bold text-slate-800">📂 File Access</span>
              </div>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getVerdictBadge(file_access.verdict)}`}>
                {file_access.verdict}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mb-2 line-clamp-2">
              Can this {isJar ? 'JAR' : 'Java program'} read, collect, or package files?
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-100">
              <span className="font-semibold text-slate-700">{file_access.capabilities.length} capabilities</span>
              <span className="font-mono text-[11px] text-slate-500">{file_access.score}/100</span>
            </div>
          </button>

          {/* Pillar 3: Command Execution */}
          <button
            onClick={() => setSelectedPillar('command')}
            className={`p-4 rounded-2xl border text-left transition-all cursor-pointer ${
              selectedPillar === 'command'
                ? 'bg-rose-50/70 border-rose-300 shadow-sm ring-2 ring-rose-400/20'
                : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-rose-600" />
                <span className="text-xs font-bold text-slate-800">🛠 Command Execution</span>
              </div>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getVerdictBadge(command_execution.verdict)}`}>
                {command_execution.verdict}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mb-2 line-clamp-2">
              Can this {isJar ? 'JAR' : 'Java program'} run OS-level commands?
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-100">
              <span className="font-semibold text-slate-700">{command_execution.capabilities.length} capabilities</span>
              <span className="font-mono text-[11px] text-slate-500">{command_execution.score}/100</span>
            </div>
          </button>

          {/* Pillar 4: Code Obfuscation */}
          <button
            onClick={() => setSelectedPillar('obfuscation')}
            className={`p-4 rounded-2xl border text-left transition-all cursor-pointer ${
              selectedPillar === 'obfuscation'
                ? 'bg-purple-50/70 border-purple-300 shadow-sm ring-2 ring-purple-400/20'
                : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <EyeOff className="w-4 h-4 text-purple-600" />
                <span className="text-xs font-bold text-slate-800">🧩 Hidden Code</span>
              </div>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getVerdictBadge(code_obfuscation.verdict)}`}>
                {code_obfuscation.verdict}
              </span>
            </div>
            <div className="text-[11px] text-slate-500 mb-2 line-clamp-2">
              Is the code unusually hard to inspect?
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-100">
              <span className="font-semibold text-slate-700">{code_obfuscation.indicators.length} indicators</span>
              <span className="font-mono text-[11px] text-slate-500">{code_obfuscation.score}/100</span>
            </div>
          </button>
        </div>
      </div>

      {/* 3. Deep-Dive Detail View for Selected Pillar */}
      <div className="p-6 bg-slate-50/70 border border-slate-200 rounded-3xl space-y-5">
        {/* Pillar Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h4 className="text-base font-bold text-slate-900">
                {selectedPillar === 'internet' && '🌐 Internet Activity Forensics'}
                {selectedPillar === 'file' && '📂 File Access & Staging Forensics'}
                {selectedPillar === 'command' && '🛠 System Command Execution Forensics'}
                {selectedPillar === 'obfuscation' && '🧩 Hidden & Hard-to-Review Code Forensics'}
              </h4>
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${
                selectedPillar === 'internet' ? getVerdictBadge(internet_activity.verdict) :
                selectedPillar === 'file' ? getVerdictBadge(file_access.verdict) :
                selectedPillar === 'command' ? getVerdictBadge(command_execution.verdict) :
                getVerdictBadge(code_obfuscation.verdict)
              }`}>
                {selectedPillar === 'internet' && internet_activity.verdict}
                {selectedPillar === 'file' && file_access.verdict}
                {selectedPillar === 'command' && command_execution.verdict}
                {selectedPillar === 'obfuscation' && code_obfuscation.verdict}
              </span>
            </div>
            <p className="text-xs text-slate-600">
              {selectedPillar === 'internet' && internet_activity.summary}
              {selectedPillar === 'file' && file_access.summary}
              {selectedPillar === 'command' && command_execution.summary}
              {selectedPillar === 'obfuscation' && code_obfuscation.summary}
            </p>
          </div>

          <div className="text-xs bg-white px-3 py-1.5 rounded-xl border border-slate-200 shrink-0 font-medium text-slate-600">
            Threat Score:{' '}
            <strong className="text-slate-900 font-mono">
              {selectedPillar === 'internet' && `${internet_activity.score}/100`}
              {selectedPillar === 'file' && `${file_access.score}/100`}
              {selectedPillar === 'command' && `${command_execution.score}/100`}
              {selectedPillar === 'obfuscation' && `${code_obfuscation.score}/100`}
            </strong>
          </div>
        </div>

        {/* Pillar Methodology Guidance Note */}
        <div className="p-3.5 bg-white rounded-2xl border border-slate-200 text-xs text-slate-600 space-y-1">
          <strong className="text-slate-900 block font-semibold">
            {selectedPillar === 'internet' && 'What SecurityScorecard looks for: Can this JAR contact external servers?'}
            {selectedPillar === 'file' && 'What SecurityScorecard looks for: Can this JAR read, collect, or package files?'}
            {selectedPillar === 'command' && 'What SecurityScorecard looks for: Can this JAR run OS-level commands?'}
            {selectedPillar === 'obfuscation' && 'What SecurityScorecard looks for: Is the code unusually hard to inspect?'}
          </strong>
          <p className="text-slate-500 leading-relaxed">
            {selectedPillar === 'internet' &&
              'A program may call home, send usage data, download extra content, or connect to services you did not expect: a plugin checking for updates from a vendor site, an app sending analytics to a metrics service, a tool uploading logs or machine details to an API, or a bundled component opening raw socket connections.'}
            {selectedPillar === 'file' &&
              'Some tools only read their own config. Others can scan directories, collect many files, or prepare them for export: a backup tool creating ZIP archives, a launcher reading files outside its normal folder, a support utility collecting logs for upload, or a suspicious tool scanning broad parts of the filesystem.'}
            {selectedPillar === 'command' &&
              'This can be legitimate for installers and admin tools, but it is also a powerful capability often seen in malware and remote-control utilities: an installer launching a system command, a build tool invoking another executable, a monitoring agent running shell commands, or a hidden routine executing commands on the host machine.'}
            {selectedPillar === 'obfuscation' &&
              'Some JARs use obfuscation or have methods that are difficult to decompile. That does not prove malware, but it makes trust harder: a commercial app protecting its code, a packed dependency with very complex bytecode, encoded strings hiding real URLs or commands, or methods that fail clean decompilation during review.'}
          </p>
        </div>

        {/* Pillar 1: Internet Activity Details */}
        {selectedPillar === 'internet' && (
          <div className="space-y-4">
            {/* Capabilities List */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Discovered Internet Capabilities ({internet_activity.capabilities.length})
              </h5>
              {internet_activity.capabilities.length > 0 ? (
                internet_activity.capabilities.map((cap, i) => (
                  <div key={i} className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {getCapabilityIcon(cap.id)}
                        <strong className="text-xs font-bold text-slate-900">{cap.name}</strong>
                      </div>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(cap.severity)}`}>
                        {cap.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600">{cap.description}</p>
                    {cap.evidence.length > 0 && (
                      <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                        <span className="text-[10px] font-sans text-slate-400 font-semibold uppercase">Evidence:</span>
                        {cap.evidence.map((ev, ei) => (
                          <span key={ei} className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded-md border border-slate-200">
                            {ev}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="p-4 bg-white rounded-2xl border border-slate-200 text-center text-xs text-slate-400">
                  No outbound socket or HTTP network communication capabilities discovered in constant pool or bytecode.
                </div>
              )}
            </div>

            {/* Extracted Endpoints */}
            {internet_activity.endpoints && internet_activity.endpoints.length > 0 && (
              <div className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
                <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Discovered Remote Endpoints &amp; C2 Hosts ({internet_activity.endpoints.length})
                </h5>
                <div className="space-y-1.5 font-mono text-xs max-h-48 overflow-y-auto">
                  {internet_activity.endpoints.map((ep, i) => (
                    <div key={i} className="flex items-center justify-between p-2 bg-slate-50 hover:bg-slate-100 rounded-xl border border-slate-200">
                      <span className="text-slate-800 break-all">{ep}</span>
                      <button
                        onClick={() => handleCopy(ep, `ep-${i}`)}
                        className="text-[11px] font-sans text-slate-500 hover:text-slate-800 ml-2 shrink-0 flex items-center gap-1"
                      >
                        {copiedItem === `ep-${i}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        {copiedItem === `ep-${i}` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Pillar 2: File Access Details */}
        {selectedPillar === 'file' && (
          <div className="space-y-4">
            {/* Capabilities List */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Discovered File Access Capabilities ({file_access.capabilities.length})
              </h5>
              {file_access.capabilities.length > 0 ? (
                file_access.capabilities.map((cap, i) => (
                  <div key={i} className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {getCapabilityIcon(cap.id)}
                        <strong className="text-xs font-bold text-slate-900">{cap.name}</strong>
                      </div>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(cap.severity)}`}>
                        {cap.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600">{cap.description}</p>
                    {cap.evidence.length > 0 && (
                      <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                        <span className="text-[10px] font-sans text-slate-400 font-semibold uppercase">Evidence:</span>
                        {cap.evidence.map((ev, ei) => (
                          <span key={ei} className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded-md border border-slate-200">
                            {ev}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="p-4 bg-white rounded-2xl border border-slate-200 text-center text-xs text-slate-400">
                  No directory traversal, credential store targeting, or archive packaging detected.
                </div>
              )}
            </div>

            {/* Targeted Paths & Databases */}
            {file_access.targeted_paths && file_access.targeted_paths.length > 0 && (
              <div className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
                <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Targeted System Locations, Folders &amp; Credential Databases ({file_access.targeted_paths.length})
                </h5>
                <div className="space-y-1.5 font-mono text-xs max-h-48 overflow-y-auto">
                  {file_access.targeted_paths.map((p, i) => (
                    <div key={i} className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-rose-800 font-semibold">
                      • {p}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Pillar 3: Command Execution Details */}
        {selectedPillar === 'command' && (
          <div className="space-y-4">
            {/* Capabilities List */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Discovered Command Execution Capabilities ({command_execution.capabilities.length})
              </h5>
              {command_execution.capabilities.length > 0 ? (
                command_execution.capabilities.map((cap, i) => (
                  <div key={i} className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        {getCapabilityIcon(cap.id)}
                        <strong className="text-xs font-bold text-slate-900">{cap.name}</strong>
                      </div>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(cap.severity)}`}>
                        {cap.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600">{cap.description}</p>
                    {cap.evidence.length > 0 && (
                      <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                        <span className="text-[10px] font-sans text-slate-400 font-semibold uppercase">Evidence:</span>
                        {cap.evidence.map((ev, ei) => (
                          <span key={ei} className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded-md border border-slate-200">
                            {ev}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="p-4 bg-white rounded-2xl border border-slate-200 text-center text-xs text-slate-400">
                  No OS shell commands, ProcessBuilder, or persistence routines detected.
                </div>
              )}
            </div>

            {/* Detected Command Strings */}
            {command_execution.detected_commands && command_execution.detected_commands.length > 0 && (
              <div className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
                <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Extracted Command Strings &amp; Shell Arguments ({command_execution.detected_commands.length})
                </h5>
                <div className="space-y-1.5 font-mono text-xs max-h-48 overflow-y-auto">
                  {command_execution.detected_commands.map((cmd, i) => (
                    <div key={i} className="flex items-center justify-between p-2 bg-slate-900 text-slate-200 rounded-xl">
                      <span className="break-all">{cmd}</span>
                      <button
                        onClick={() => handleCopy(cmd, `cmd-${i}`)}
                        className="text-[11px] font-sans text-slate-400 hover:text-white ml-2 shrink-0 flex items-center gap-1"
                      >
                        {copiedItem === `cmd-${i}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        {copiedItem === `cmd-${i}` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Pillar 4: Code Obfuscation Details */}
        {selectedPillar === 'obfuscation' && (
          <div className="space-y-4">
            {/* Obfuscator Detectors Bar */}
            <div className="p-4 bg-white rounded-2xl border border-slate-200 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                    Detected Obfuscator Software
                  </span>
                  <div className="flex flex-wrap items-center gap-2">
                    {code_obfuscation.obfuscators.length > 0 ? (
                      code_obfuscation.obfuscators.map((obf, i) => (
                        <span key={i} className="text-xs font-bold px-2.5 py-1 bg-purple-100 text-purple-800 rounded-lg border border-purple-200">
                          {obf}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs font-medium text-slate-500">
                        None detected (Transparent / Standard compilation)
                      </span>
                    )}
                  </div>
                </div>

                {code_obfuscation.single_letter_class_ratio !== undefined && code_obfuscation.total_classes && (
                  <div className="text-right">
                    <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                      Obfuscated Class Ratio
                    </span>
                    <span className="font-mono text-sm font-bold text-slate-900">
                      {Math.round(code_obfuscation.single_letter_class_ratio * 100)}% ({code_obfuscation.obfuscated_classes_count}/{code_obfuscation.total_classes} classes)
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Indicators List */}
            <div className="space-y-3">
              <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Obfuscation &amp; Anti-Review Indicators ({code_obfuscation.indicators.length})
              </h5>
              {code_obfuscation.indicators.length > 0 ? (
                code_obfuscation.indicators.map((ind, i) => (
                  <div key={i} className="p-4 bg-white rounded-2xl border border-slate-200 space-y-1.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <strong className="text-xs font-bold text-slate-900">{ind.name}</strong>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(ind.severity)}`}>
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 leading-relaxed">{ind.detail}</p>
                  </div>
                ))
              ) : (
                <div className="p-4 bg-white rounded-2xl border border-slate-200 text-center text-xs text-slate-400">
                  Bytecode contains clean, readable method names and standard package hierarchies.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
