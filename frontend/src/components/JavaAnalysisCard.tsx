import React, { useState } from 'react';
import {
  Coffee,
  ShieldAlert,
  Layers,
  Copy,
  Check,
  Code,
  Bug,
  Binary,
  AlertTriangle,
  ShieldCheck,
  Globe,
  FolderSearch,
  Terminal,
  EyeOff
} from 'lucide-react';
import { JavaAnalysisData, Finding } from '../types';
import { JavaBehavioralForensics } from './JavaBehavioralForensics';

interface JavaAnalysisCardProps {
  javaInfo?: JavaAnalysisData;
  filename?: string;
  findings?: Finding[];
}

export const JavaAnalysisCard: React.FC<JavaAnalysisCardProps> = ({
  javaInfo,
  filename = 'application.java'
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'behavioral' | 'apis' | 'code' | 'binaries' | 'rat'>('overview');
  const [copiedCode, setCopiedCode] = useState(false);

  if (!javaInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Coffee className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No Java source or bytecode analysis data available for this file.</p>
      </div>
    );
  }

  const {
    java_subtype = 'source',
    classes_count = 1,
    classes_list = [],
    main_class,
    premain_class,
    agent_class,
    permissions,
    code_preview = '',
    class_info = {},
    dangerous_apis = [],
    embedded_binaries = [],
    rat_detections = [],
    risk_score = 0,
    risk_level = 'LOW'
  } = javaInfo;

  const isAllPermissions = permissions && permissions.toLowerCase().includes('all-permissions');
  const isAgentHook = Boolean(premain_class || agent_class);

  const handleCopyCode = () => {
    navigator.clipboard.writeText(code_preview);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

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
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-amber-50 text-amber-600 rounded-2xl shrink-0">
            <Coffee className="w-8 h-8" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-xl font-bold text-slate-900">
                {java_subtype === 'source' && 'Java Source Code (.java) Forensic Security Analysis'}
                {java_subtype === 'class' && 'Java Bytecode (.class) Constant Pool & Disassembly'}
                {java_subtype === 'jar' && 'Java Archive (.jar / .war) Deep Forensic Inspection'}
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                {filename}
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-bold uppercase bg-slate-100 text-slate-700 border border-slate-200">
                Subtype: {java_subtype}
              </span>
              <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${getRiskBadgeColor(risk_level)}`}>
                Risk: {risk_level} ({risk_score}/100)
              </span>
              {isAgentHook && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  ⚠️ Premain Java Agent Hook
                </span>
              )}
              {isAllPermissions && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  ⚠️ all-permissions Requested
                </span>
              )}
              {rat_detections.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-600 text-white">
                  RAT Signature: {rat_detections.join(', ')}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              {java_subtype === 'source' && 'AST static security audit for shell execution, unmanaged memory (sun.misc.Unsafe), dynamic reflection, and JNDI lookups.'}
              {java_subtype === 'class' && 'JVM binary structure disassembly, constant pool method resolution, and dangerous system API call auditing.'}
              {java_subtype === 'jar' && 'Archive manifest analysis (Main-Class, Premain Java Agent instrumentation), bytecode scanning, and native binary inspection.'}
            </p>
          </div>
        </div>

        {/* Quick Stats Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Classes</span>
            <strong className="text-slate-900">{classes_count}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Dangerous APIs</span>
            <strong className={dangerous_apis.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {dangerous_apis.length}
            </strong>
          </div>
          {class_info.java_version && (
            <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
              <span className="text-[10px] uppercase text-slate-400 block font-sans">Target JVM</span>
              <strong className="text-indigo-600">{class_info.java_version}</strong>
            </div>
          )}
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Native Binaries</span>
            <strong className={embedded_binaries.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {embedded_binaries.length}
            </strong>
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
          <Layers className="w-3.5 h-3.5" />
          Overview &amp; Entry Points
        </button>

        <button
          onClick={() => setActiveTab('behavioral')}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
            activeTab === 'behavioral'
              ? 'bg-rose-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Bug className="w-3.5 h-3.5 text-rose-400" />
          Behavioral Forensics (STRRAT Triage)
        </button>

        <button
          onClick={() => setActiveTab('apis')}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'apis'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          Dangerous JVM APIs ({dangerous_apis.length})
        </button>

        {code_preview && (
          <button
            onClick={() => setActiveTab('code')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'code'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            {java_subtype === 'jar' ? 'Manifest & Structure' : 'Source / Disassembly View'}
          </button>
        )}

        {embedded_binaries.length > 0 && (
          <button
            onClick={() => setActiveTab('binaries')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'binaries'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Binary className="w-3.5 h-3.5" />
            Native Payloads ({embedded_binaries.length})
          </button>
        )}

        {rat_detections.length > 0 && (
          <button
            onClick={() => setActiveTab('rat')}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-xl transition-all ${
              activeTab === 'rat'
                ? 'bg-slate-900 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Bug className="w-3.5 h-3.5" />
            RAT Signatures ({rat_detections.length})
          </button>
        )}
      </div>

      {/* Tab: Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Metadata Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Subtype &amp; Target
              </span>
              <span className="font-mono text-sm font-semibold text-slate-800 uppercase">
                {java_subtype} {class_info.java_version ? `(${class_info.java_version})` : ''}
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Executable Entry Point
              </span>
              <span className="font-mono text-sm font-semibold text-slate-800 truncate block" title={main_class || 'None'}>
                {main_class || 'Library / Non-Executable'}
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Java Agent Hook (Premain)
              </span>
              <span className={`font-mono text-sm font-semibold ${premain_class ? 'text-rose-600' : 'text-slate-800'}`}>
                {premain_class || agent_class || 'None'}
              </span>
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Security Sandbox Permissions
              </span>
              <span className={`text-sm font-semibold ${isAllPermissions ? 'text-rose-600 font-bold' : 'text-slate-800'}`}>
                {permissions || 'Standard Sandbox'}
              </span>
            </div>
          </div>

          {/* Critical Warnings: Premain Java Agent */}
          {isAgentHook && (
            <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 flex items-start gap-3 text-rose-800">
              <ShieldAlert className="w-5 h-5 shrink-0 text-rose-600" />
              <div>
                <strong className="text-xs font-bold block">
                  Java Instrumentation Agent Detected (Premain-Class: {premain_class || agent_class})
                </strong>
                <p className="text-xs text-rose-700 mt-0.5 leading-relaxed">
                  Archive specifies a Java Agent entry point via <code>Premain-Class</code> or <code>Agent-Class</code>.
                  Java agents execute before application startup with unrestricted access to rewrite bytecode, hook classes,
                  and monitor in-memory JVM secrets, a technique heavily abused by stealthy JVM rootkits and surveillance malware.
                </p>
              </div>
            </div>
          )}

          {/* Compiled Class Info Grid */}
          {class_info && class_info.constant_pool_count && (
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-100 space-y-3">
              <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                Compiled Bytecode Structure &amp; Constant Pool
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
                  <span className="text-[10px] uppercase text-slate-400 block font-sans">Constant Pool</span>
                  <strong className="text-slate-900">{class_info.constant_pool_count} entries</strong>
                </div>
                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
                  <span className="text-[10px] uppercase text-slate-400 block font-sans">Methods</span>
                  <strong className="text-slate-900">{class_info.methods_count || 0} methods</strong>
                </div>
                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
                  <span className="text-[10px] uppercase text-slate-400 block font-sans">Fields</span>
                  <strong className="text-slate-900">{class_info.fields_count || 0} fields</strong>
                </div>
                <div className="p-3 bg-white rounded-xl border border-slate-200 text-center">
                  <span className="text-[10px] uppercase text-slate-400 block font-sans">Interfaces</span>
                  <strong className="text-slate-900">{class_info.interfaces_count || 0} interfaces</strong>
                </div>
              </div>
            </div>
          )}

          {/* Classes Preview */}
          {classes_list && classes_list.length > 0 && (
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Contained Bytecode Classes ({classes_count})
                </span>
              </div>
              <div className="max-h-48 overflow-y-auto font-mono text-xs text-slate-700 space-y-1">
                {classes_list.slice(0, 30).map((cls, idx) => (
                  <div key={idx} className="truncate">• {cls}</div>
                ))}
                {classes_list.length > 30 && (
                  <div className="text-slate-400 italic text-[11px]">+ {classes_list.length - 30} more classes</div>
                )}
              </div>
            </div>
          )}

          {/* Behavioral Forensics Quick Triage (4 Pillars) */}
          {javaInfo.behavioral_analysis && (
            <div className="p-5 bg-gradient-to-br from-slate-50 to-slate-100/60 rounded-3xl border border-slate-200 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-rose-600" />
                    SecurityScorecard Behavioral Forensics Triage
                  </h4>
                  <p className="text-xs text-slate-500">
                    Static audit across 4 core behavioral pillars (Internet, Filesystem, Commands, Obfuscation).
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('behavioral')}
                  className="text-xs font-bold text-rose-600 hover:text-rose-700 bg-white hover:bg-rose-50 px-3 py-1.5 rounded-xl border border-rose-200 transition-colors shadow-sm cursor-pointer"
                >
                  View Deep Forensics &amp; STRRAT Report →
                </button>
              </div>

              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="p-3 bg-white rounded-2xl border border-slate-200 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 flex items-center gap-1">
                      <Globe className="w-3.5 h-3.5 text-sky-600" /> Internet
                    </span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      javaInfo.behavioral_analysis.internet_activity.verdict === 'SUSPICIOUS' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                      javaInfo.behavioral_analysis.internet_activity.verdict === 'POTENTIAL' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                      'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}>
                      {javaInfo.behavioral_analysis.internet_activity.verdict}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {javaInfo.behavioral_analysis.internet_activity.capabilities.length} capabilities detected
                  </div>
                </div>

                <div className="p-3 bg-white rounded-2xl border border-slate-200 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 flex items-center gap-1">
                      <FolderSearch className="w-3.5 h-3.5 text-amber-600" /> File Access
                    </span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      javaInfo.behavioral_analysis.file_access.verdict === 'SUSPICIOUS' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                      javaInfo.behavioral_analysis.file_access.verdict === 'POTENTIAL' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                      'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}>
                      {javaInfo.behavioral_analysis.file_access.verdict}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {javaInfo.behavioral_analysis.file_access.capabilities.length} capabilities detected
                  </div>
                </div>

                <div className="p-3 bg-white rounded-2xl border border-slate-200 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 flex items-center gap-1">
                      <Terminal className="w-3.5 h-3.5 text-rose-600" /> Commands
                    </span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      javaInfo.behavioral_analysis.command_execution.verdict === 'SUSPICIOUS' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                      javaInfo.behavioral_analysis.command_execution.verdict === 'POTENTIAL' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                      'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}>
                      {javaInfo.behavioral_analysis.command_execution.verdict}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {javaInfo.behavioral_analysis.command_execution.capabilities.length} capabilities detected
                  </div>
                </div>

                <div className="p-3 bg-white rounded-2xl border border-slate-200 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-700 flex items-center gap-1">
                      <EyeOff className="w-3.5 h-3.5 text-purple-600" /> Obfuscation
                    </span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                      javaInfo.behavioral_analysis.code_obfuscation.verdict === 'OBFUSCATED' ? 'bg-rose-50 text-rose-700 border-rose-200' :
                      javaInfo.behavioral_analysis.code_obfuscation.verdict === 'SUSPICIOUS' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                      'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}>
                      {javaInfo.behavioral_analysis.code_obfuscation.verdict}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {javaInfo.behavioral_analysis.code_obfuscation.indicators.length} indicators flagged
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Behavioral Forensics & STRRAT Case Study */}
      {activeTab === 'behavioral' && (
        <JavaBehavioralForensics
          behavioral={javaInfo.behavioral_analysis}
          filename={filename}
          isJar={java_subtype === 'jar'}
        />
      )}

      {/* Tab: Dangerous APIs */}
      {activeTab === 'apis' && (
        <div className="space-y-4">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
            <h4 className="text-sm font-bold text-slate-900">Sensitive &amp; Malicious JVM API Signatures</h4>
            <p className="text-xs text-slate-500">
              Heuristic matching for OS shell spawning, raw memory manipulation, JNDI lookups (Log4Shell), and dynamic reflection.
            </p>
          </div>

          {dangerous_apis.length > 0 ? (
            <div className="space-y-3">
              {dangerous_apis.map((api, idx) => (
                <div
                  key={idx}
                  className="p-4 bg-slate-50 hover:bg-slate-100/80 transition-all rounded-2xl border border-slate-200 space-y-2.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md border ${getSeverityBadge(api.severity)}`}>
                        {api.severity}
                      </span>
                      {api.category && (
                        <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-md bg-slate-200 text-slate-700">
                          {api.category}
                        </span>
                      )}
                      <strong className="text-xs font-bold text-slate-900">{api.title}</strong>
                      {api.class_file && (
                        <span className="text-[11px] font-mono text-slate-500">({api.class_file})</span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {api.cwe && (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-50 text-amber-700 border border-amber-200 rounded-md">
                          {api.cwe}
                        </span>
                      )}
                      {api.owasp && (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-md">
                          {api.owasp}
                        </span>
                      )}
                      {api.mitre && (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-200 rounded-md">
                          MITRE {api.mitre} ({api.mitre_name})
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="font-mono text-xs text-rose-700 font-semibold bg-white p-2 rounded-xl border border-slate-200 break-all">
                    {api.api}
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">{api.description}</p>

                  {/* Threat Explanation */}
                  {api.risk_explanation && (
                    <div className="p-3 bg-amber-50/80 rounded-xl border border-amber-200 text-xs text-amber-900 space-y-1">
                      <span className="font-bold flex items-center gap-1.5 text-amber-800">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                        Threat Model &amp; Exploitation Rationale:
                      </span>
                      <p className="leading-relaxed text-amber-800/90">{api.risk_explanation}</p>
                    </div>
                  )}

                  {/* Remediation */}
                  {api.remediation && (
                    <div className="p-3 bg-emerald-50/80 rounded-xl border border-emerald-200 text-xs text-emerald-900 space-y-1">
                      <span className="font-bold flex items-center gap-1.5 text-emerald-800">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                        Remediation &amp; Secure Pattern:
                      </span>
                      <p className="leading-relaxed text-emerald-800/90">{api.remediation}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs">
              No dangerous JVM API calls or suspicious execution patterns detected.
            </div>
          )}
        </div>
      )}

      {/* Tab: Code Preview / Manifest */}
      {activeTab === 'code' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
              {java_subtype === 'jar' ? 'Manifest & Archive Descriptor' : 'Source Code / Bytecode Preview'}
            </span>
            <button
              onClick={handleCopyCode}
              className="flex items-center gap-1 text-xs px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition-all"
            >
              {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedCode ? 'Copied' : 'Copy Content'}
            </button>
          </div>
          <div className="bg-slate-950 text-slate-200 p-4 rounded-2xl font-mono text-xs max-h-96 overflow-y-auto leading-relaxed whitespace-pre-wrap">
            {code_preview}
          </div>
        </div>
      )}

      {/* Tab: Embedded Native Payloads */}
      {activeTab === 'binaries' && (
        <div className="space-y-4">
          <div className="p-4 bg-amber-50 rounded-2xl border border-amber-200 text-amber-800 text-xs space-y-1">
            <strong className="font-bold block">Embedded Native Operating System Executables ({embedded_binaries.length} Files)</strong>
            <p>
              JAR archives bundling native DLLs, ELF libraries, or shell scripts frequently extract and execute them
              to bypass JVM sandbox constraints or deploy second-stage malware payloads.
            </p>
          </div>

          <div className="space-y-2">
            {embedded_binaries.map((bin, i) => (
              <div key={i} className="p-3 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs font-mono">
                <span className="text-rose-700 font-semibold">{bin}</span>
                <span className="text-[10px] px-2 py-0.5 bg-rose-100 text-rose-800 rounded font-bold">
                  NATIVE PAYLOAD
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab: RAT Signatures */}
      {activeTab === 'rat' && (
        <div className="space-y-4">
          <div className="p-4 bg-rose-50 rounded-2xl border border-rose-200 text-rose-800 text-xs space-y-1">
            <strong className="font-bold block">Known Java Remote Access Trojan (RAT) Signatures Detected</strong>
            <p>
              Bytecode package paths and manifest configurations match structural signatures of known Java malware families.
            </p>
          </div>

          <div className="space-y-2">
            {rat_detections.map((rat, i) => (
              <div key={i} className="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex items-center justify-between text-xs">
                <div>
                  <strong className="text-slate-900 text-sm block">{rat}</strong>
                  <span className="text-slate-500">Cross-platform Java Remote Access Trojan / Infostealer</span>
                </div>
                <span className="text-xs px-2.5 py-1 bg-rose-600 text-white rounded-xl font-bold">
                  MALICIOUS SIGNATURE
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
