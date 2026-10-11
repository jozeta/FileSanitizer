import React, { useState } from 'react';
import {
  FileSpreadsheet,
  Code,
  ShieldAlert,
  Copy,
  Check,
  Layers,
  FileCode,
  Zap,
  Globe,
  MousePointer,
  EyeOff,
  Lock,
  Table,
  ExternalLink
} from 'lucide-react';
import { OfficeTriageInfo, Finding, AntiAnalysisInfo } from '../types';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';
import { findReferencedJob } from '../utils/crossFileReferences';
import { ReferencedText } from './ReferencedFileLink';

interface OfficeTriageCardProps {
  officeInfo?: OfficeTriageInfo;
  filename?: string;
  findings?: Finding[];
  antiAnalysis?: AntiAnalysisInfo;
  workspaceJobs?: any[];
  onSelectJob?: (newJobId: string) => void;
}

export const OfficeTriageCard: React.FC<OfficeTriageCardProps> = ({
  officeInfo,
  filename = 'document',
  findings = [],
  antiAnalysis,
  workspaceJobs,
  onSelectJob,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'macros' | 'capabilities' | 'stomping' | 'ole' | 'relationships' | 'excel' | 'powerpoint' | 'anti_analysis'>('macros');
  const [selectedModuleIdx, setSelectedModuleIdx] = useState<number>(0);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  const {
    has_macros = false,
    macro_details = [],
    macro_modules = [],
    vba_capabilities = {},
    vba_stomping = { is_stomped: false },
    vba_purging = { is_purged: false },
    activex_objects = [],
    ole_objects = [],
    remote_templates = [],
    urls = []
  } = officeInfo || {};

  const excelAnalysis = officeInfo?.excel_analysis;
  const powerpointAnalysis = officeInfo?.powerpoint_analysis;

  const malwareFindings = findings.filter(f => f.category === 'malware' || f.category === 'yara');
  const embeddedFindings = findings.filter(f => f.title.toLowerCase().includes('payload') || f.title.toLowerCase().includes('embedded ole'));
  const ddeFindings = findings.filter(f => f.title.toLowerCase().includes('dde') || f.title.toLowerCase().includes('dynamic data exchange'));
  const xlmFindings = findings.filter(f => f.title.toLowerCase().includes('xlm') || f.title.toLowerCase().includes('excel 4.0'));
  const oledumpData = (officeInfo as any)?.oledump || null;

  const currentModule = macro_modules[selectedModuleIdx];

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const capabilitiesCount = Object.values(vba_capabilities).reduce((acc, curr) => acc + (curr?.length || 0), 0);

  const referencedJobsInOffice = React.useMemo(() => {
    if (!workspaceJobs || workspaceJobs.length === 0) return [];
    const matched: any[] = [];
    const seen = new Set<string>();

    const checkToken = (token?: string) => {
      if (!token) return;
      const ref = findReferencedJob(token, workspaceJobs);
      if (ref && !seen.has(ref.jobId)) {
        seen.add(ref.jobId);
        matched.push(ref);
      }
    };

    // Check macro module codes
    macro_modules.forEach(m => {
      if (m.code) {
        workspaceJobs.forEach(wj => {
          if (wj.filename && m.code.toLowerCase().includes(wj.filename.toLowerCase())) {
            checkToken(wj.filename);
          }
        });
      }
    });

    // Check remote templates & URLs
    remote_templates.forEach(t => {
      const tgt = typeof t === 'string' ? t : t?.target;
      if (tgt) checkToken(tgt);
    });
    urls.forEach(u => checkToken(u));

    // Check ole objects
    ole_objects.forEach(o => checkToken(o));

    return matched;
  }, [workspaceJobs, macro_modules, remote_templates, urls, ole_objects]);

  if (!officeInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <FileSpreadsheet className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No Office format triage metadata available for this file.</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-blue-50 text-blue-600 rounded-2xl shrink-0">
            <FileSpreadsheet className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Microsoft Office &amp; OpenXML Deep Triage
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                {filename}
              </span>
              {has_macros && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-700 border border-rose-300 animate-pulse">
                  VBA Macros Active
                </span>
              )}
              {vba_stomping.is_stomped && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-50 text-purple-700 border border-purple-300">
                  ⚠️ VBA Stomped (P-Code)
                </span>
              )}
              {excelAnalysis?.very_hidden_sheets && excelAnalysis.very_hidden_sheets.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-50 text-purple-700 border border-purple-300 animate-pulse">
                  ⚠️ {excelAnalysis.very_hidden_sheets.length} 'Very Hidden' Sheet(s)
                </span>
              )}
              {excelAnalysis?.power_query_queries && excelAnalysis.power_query_queries.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-700 border border-rose-300 animate-pulse">
                  ⚠️ Power Query Exfiltration
                </span>
              )}
              {powerpointAnalysis?.hover_actions && powerpointAnalysis.hover_actions.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-700 border border-rose-300 animate-pulse">
                  ⚠️ PowerPoint Mouse-Over Action Trap
                </span>
              )}
              {remote_templates.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-50 text-amber-700 border border-amber-300">
                  Template Injection
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Deep static inspection of VBA macro streams, olevba modules, P-code stomping, OLE objects, and remote templates.
            </p>
          </div>
        </div>

        {/* Quick Metrics Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Modules</span>
            <strong className="text-slate-900">{macro_modules.length}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Capabilities</span>
            <strong className={capabilitiesCount > 0 ? 'text-amber-600' : 'text-slate-900'}>{capabilitiesCount}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Remote URLs</span>
            <strong className="text-slate-900">{urls.length}</strong>
          </div>
        </div>
      </div>

      {/* Prominent Malware / Antivirus Detection Alert */}
      {malwareFindings.length > 0 && (
        <div className="p-4 bg-rose-50 border border-rose-300 rounded-2xl flex items-start gap-3.5 text-xs text-rose-950 shadow-xs">
          <div className="p-2 bg-rose-600 text-white rounded-xl shrink-0 mt-0.5 font-bold">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div className="space-y-1 flex-1">
            <div className="flex items-center justify-between">
              <h4 className="font-bold text-sm text-rose-900">
                Active Malware Signature Detected in Document ({malwareFindings.length})
              </h4>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-600 text-white uppercase tracking-wider animate-pulse">
                Critical Threat
              </span>
            </div>
            <p className="text-rose-800 leading-relaxed">
              Security scanners identified known malicious signatures inside this Office container. File execution or standard macro opening should be restricted.
            </p>
            <div className="space-y-1 pt-1">
              {malwareFindings.map((mf, idx) => (
                <div key={idx} className="p-2 bg-white/80 rounded-xl border border-rose-200 text-rose-900 font-mono text-[11px] flex items-center justify-between">
                  <div>
                    <strong className="text-rose-700">{mf.title}</strong>
                    {mf.description && <span className="text-slate-600 block text-[10px] font-sans">{mf.description}</span>}
                  </div>
                  <span className="px-1.5 py-0.5 bg-rose-100 text-rose-800 rounded text-[10px] font-bold uppercase shrink-0">
                    {mf.category}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2 overflow-x-auto text-xs font-semibold">
        <button
          onClick={() => setActiveSubTab('macros')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'macros'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Code className="w-3.5 h-3.5" />
          <span>VBA Modules ({macro_modules.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('capabilities')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'capabilities'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Zap className="w-3.5 h-3.5 text-amber-500" />
          <span>VBA Capabilities ({capabilitiesCount})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('stomping')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'stomping'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-purple-500" />
          <span>Stomping &amp; Evasion {vba_stomping.is_stomped && '⚠️'}</span>
        </button>

        <button
          onClick={() => setActiveSubTab('ole')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'ole'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-blue-500" />
          <span>OLE Streams &amp; Objects</span>
        </button>

        <button
          onClick={() => setActiveSubTab('relationships')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'relationships'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-3.5 h-3.5 text-emerald-500" />
          <span>Templates &amp; External URLs ({remote_templates.length + urls.length})</span>
        </button>

        {(excelAnalysis || filename.match(/\.(xlsx?|xlsm)$/i)) && (
          <button
            onClick={() => setActiveSubTab('excel')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'excel'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Table className="w-3.5 h-3.5 text-emerald-500" />
            <span>
              Excel &amp; Power Query
              {(excelAnalysis?.very_hidden_sheets?.length || 0) > 0 ? ` ⚠️ (${excelAnalysis?.very_hidden_sheets?.length})` : ''}
            </span>
          </button>
        )}

        {(powerpointAnalysis || filename.match(/\.(pptx?|pptm)$/i)) && (
          <button
            onClick={() => setActiveSubTab('powerpoint')}
            className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
              activeSubTab === 'powerpoint'
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <MousePointer className="w-3.5 h-3.5 text-amber-500" />
            <span>
              PowerPoint Actions
              {(powerpointAnalysis?.hover_actions?.length || 0) > 0 ? ` ⚠️ (${powerpointAnalysis?.hover_actions?.length})` : ''}
            </span>
          </button>
        )}

        <button
          onClick={() => setActiveSubTab('anti_analysis')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'anti_analysis'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
          <span>Anti-Analysis & Evasion</span>
          {Boolean(antiAnalysis?.techniques && antiAnalysis.techniques.length > 0) && (
            <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold">
              {antiAnalysis?.techniques.length}
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: VBA Modules & Code Viewer */}
      {activeSubTab === 'macros' && (
        <div className="space-y-4">
          {macro_modules.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No VBA macro modules detected in this document.
            </div>
          ) : (
            <div className="space-y-4">
              {referencedJobsInOffice.length > 0 && (
                <div className="p-4 bg-indigo-50/80 border border-indigo-200 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-xs">
                  <div className="flex items-center gap-2.5 text-indigo-950 font-bold">
                    <Zap className="w-4 h-4 text-indigo-600 shrink-0" />
                    <span>Referenced Dropper / C2 Artifacts in Workspace:</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {referencedJobsInOffice.map((rj, idx) => (
                      <button
                        key={idx}
                        onClick={() => onSelectJob && onSelectJob(rj.job_id || rj.jobId)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-indigo-300 hover:border-indigo-500 text-indigo-700 hover:text-indigo-900 rounded-xl font-bold font-mono shadow-2xs transition-colors cursor-pointer"
                        title={`Jump to analyzed file ${rj.filename}`}
                      >
                        <span>{rj.filename}</span>
                        <ExternalLink className="w-3 h-3 text-indigo-500" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                {/* Module Selector Sidebar */}
                <div className="lg:col-span-1 space-y-1.5 border border-slate-200 rounded-2xl p-2 bg-slate-50/50">
                  <span className="text-[10px] uppercase font-bold text-slate-400 px-2 block">
                    Macro Modules ({macro_modules.length})
                  </span>
                  {macro_modules.map((m, idx) => (
                    <button
                      key={idx}
                      onClick={() => setSelectedModuleIdx(idx)}
                      className={`w-full text-left p-2.5 rounded-xl text-xs font-mono transition-all flex items-center justify-between cursor-pointer ${
                        selectedModuleIdx === idx
                          ? 'bg-white shadow-xs text-indigo-700 font-bold border border-indigo-200'
                          : 'text-slate-700 hover:bg-slate-100'
                      }`}
                    >
                      <div className="truncate">
                        <div>{m.name}</div>
                        <div className="text-[10px] text-slate-400 font-normal truncate">{m.stream}</div>
                      </div>
                      <FileCode className="w-3.5 h-3.5 shrink-0 opacity-60" />
                    </button>
                  ))}
                </div>

                {/* Code Viewer */}
                <div className="lg:col-span-3 border border-slate-200 rounded-2xl overflow-hidden bg-slate-50 text-slate-800 font-mono text-xs">
                  <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-800">{currentModule?.name}</span>
                      <span className="text-[11px] text-slate-500">({currentModule?.stream})</span>
                    </div>
                    <button
                      onClick={() => currentModule && handleCopyCode(currentModule.code)}
                      className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedCode ? 'Copied' : 'Copy VBA'}</span>
                    </button>
                  </div>

                  <div className="p-4 max-h-[500px] overflow-y-auto space-y-0.5 bg-white">
                    {(currentModule?.code || '').split('\n').map((line, lIdx) => (
                      <div key={lIdx} className="flex hover:bg-slate-50 leading-5">
                        <span className="w-10 select-none text-slate-400 text-right pr-3 shrink-0">
                          {lIdx + 1}
                        </span>
                        <span className="whitespace-pre text-slate-800">
                          {workspaceJobs && workspaceJobs.length > 0 ? (
                            <ReferencedText text={line} workspaceJobs={workspaceJobs} onSelectJob={onSelectJob} />
                          ) : (
                            line || ' '
                          )}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Capabilities Breakdown */}
      {activeSubTab === 'capabilities' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(vba_capabilities).map(([cat, kwList]) => (
              <div key={cat} className="p-4 bg-slate-50/70 border border-slate-200 rounded-2xl space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-xs uppercase tracking-wide text-slate-800">
                    {cat.replace(/_/g, ' ')}
                  </h4>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800">
                    {kwList.length} hit{kwList.length > 1 ? 's' : ''}
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {kwList.map((kw: any, i: number) => {
                    const label = typeof kw === 'string' ? kw : (kw?.label || 'Capability');
                    const count = typeof kw === 'object' ? kw?.count : undefined;
                    const samples = typeof kw === 'object' && Array.isArray(kw?.samples) ? kw.samples : [];
                    const sampleTooltip = samples.length > 0 ? `Matched samples: ${samples.join(', ')}` : undefined;

                    return (
                      <div
                        key={i}
                        title={sampleTooltip}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-white border border-slate-200 rounded-lg text-[11px] font-mono font-medium text-slate-800 shadow-2xs hover:border-indigo-300 transition-colors"
                      >
                        <span className="font-semibold">{label}</span>
                        {count !== undefined && count > 1 && (
                          <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                            x{count}
                          </span>
                        )}
                        {samples.length > 0 && (
                          <span className="text-[10px] text-slate-500 font-sans italic max-w-[140px] truncate">
                            ({samples[0]})
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {macro_details.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700">
                Detailed Keyword Analysis (olevba)
              </div>
              <div className="divide-y divide-slate-100 max-h-60 overflow-y-auto font-mono text-xs">
                {macro_details.map((item, i) => (
                  <div key={i} className="p-3 flex items-start justify-between gap-4 hover:bg-slate-50">
                    <div>
                      <span className="font-bold text-indigo-700 mr-2">{item.keyword}</span>
                      <span className="text-slate-600 font-sans">{item.description}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-100 text-slate-600 shrink-0">
                      {item.type}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: VBA Stomping & Purging */}
      {activeSubTab === 'stomping' && (
        <div className="space-y-4 text-xs">
          <div className="p-4 bg-purple-50/50 border border-purple-200 rounded-2xl space-y-2">
            <h4 className="font-bold text-purple-950 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-600" />
              <span>VBA Stomping &amp; P-Code Divergence</span>
            </h4>
            <p className="text-purple-900 leading-relaxed">
              VBA Stomping occurs when the source code in a VBA module is wiped or replaced with benign code, while the compiled
              PerformanceCache bytecode (P-code) remains active. In target versions of Microsoft Office, the application executes
              the compiled P-code directly, bypassing source-code-only antimalware scanners.
            </p>
            <div className="mt-3 flex items-center gap-3">
              <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                vba_stomping.is_stomped ? 'bg-rose-600 text-white' : 'bg-emerald-100 text-emerald-800'
              }`}>
                {vba_stomping.is_stomped ? '⚠️ VOMP / STOMPING DETECTED' : '✓ Source and P-Code Aligned'}
              </span>
              <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                vba_purging.is_purged ? 'bg-amber-600 text-white' : 'bg-slate-100 text-slate-700'
              }`}>
                {vba_purging.is_purged ? 'VBA Purged' : 'No Purging Detected'}
              </span>
            </div>
          </div>

          {vba_stomping.details && vba_stomping.details.length > 0 && (
            <div className="border border-slate-200 rounded-2xl p-4 bg-white space-y-2 font-mono text-xs">
              <span className="font-bold text-slate-700 font-sans block">Stomping Inspection Evidence:</span>
              {vba_stomping.details.map((d, i) => (
                <div key={i} className="text-slate-600 bg-slate-50 p-2 rounded-lg">
                  {d}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 4: OLE Streams */}
      {activeSubTab === 'ole' && (
        <div className="space-y-4 text-xs">
          {/* Didier Stevens oledump Streams */}
          {oledumpData && oledumpData.streams && oledumpData.streams.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
              <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-blue-600" />
                  <span>Didier Stevens oledump Stream Hierarchy ({oledumpData.streams.length} streams parsed)</span>
                </div>
                {oledumpData.macro_streams_count > 0 && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800">
                    {oledumpData.macro_streams_count} Macro Streams (M)
                  </span>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200">
                    <tr>
                      <th className="px-3.5 py-2">#</th>
                      <th className="px-3.5 py-2">Indicator</th>
                      <th className="px-3.5 py-2">Stream Path / Name</th>
                      <th className="px-3.5 py-2 text-right">Size</th>
                      <th className="px-3.5 py-2">Type</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {oledumpData.streams.map((s: any, idx: number) => {
                      const isMacro = s.indicator === 'M' || s.has_macro;
                      const isSmallMacro = s.indicator === 'm';
                      return (
                        <tr key={idx} className={isMacro ? 'bg-rose-50/40 hover:bg-rose-50/70' : 'hover:bg-slate-50'}>
                          <td className="px-3.5 py-2 text-slate-500">{s.index || idx + 1}</td>
                          <td className="px-3.5 py-2">
                            {isMacro ? (
                              <span className="px-1.5 py-0.2 rounded font-bold text-[10px] bg-rose-600 text-white">
                                M
                              </span>
                            ) : isSmallMacro ? (
                              <span className="px-1.5 py-0.2 rounded font-bold text-[10px] bg-amber-500 text-white">
                                m
                              </span>
                            ) : (
                              <span className="text-slate-300">-</span>
                            )}
                          </td>
                          <td className="px-3.5 py-2 font-semibold text-slate-800 break-all">
                            {s.name || s.path || 'Stream'}
                          </td>
                          <td className="px-3.5 py-2 text-right text-slate-600 font-sans">
                            {s.size ? `${(s.size / 1024).toFixed(1)} KB` : '0 B'}
                          </td>
                          <td className="px-3.5 py-2 text-slate-500 font-sans text-[11px]">
                            {s.stream_type || (isMacro ? 'VBA Module' : 'Storage / Stream')}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Dangerous Embedded Payloads & Discovered Objects */}
          {embeddedFindings.length > 0 && (
            <div className="border border-rose-200 rounded-2xl overflow-hidden bg-rose-50/30">
              <div className="bg-rose-100/70 px-4 py-2.5 border-b border-rose-200 font-bold text-rose-950 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-700" />
                  <span>Embedded Payload Findings ({embeddedFindings.length})</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white">
                  Payload Objects
                </span>
              </div>
              <div className="divide-y divide-rose-100 p-3 space-y-2">
                {embeddedFindings.map((ef, idx) => (
                  <div key={idx} className="p-3 bg-white rounded-xl border border-rose-200 shadow-2xs space-y-1">
                    <div className="flex items-center justify-between">
                      <strong className="text-rose-900 font-bold text-xs">{ef.title}</strong>
                      <span className="px-2 py-0.2 rounded text-[10px] font-bold bg-rose-100 text-rose-800 uppercase">
                        {ef.severity}
                      </span>
                    </div>
                    <p className="text-slate-600 text-xs">{ef.description}</p>
                    {ef.details && (
                      <div className="pt-1 text-[11px] font-mono text-slate-500">
                        {Object.entries(ef.details).map(([k, v]) => (
                          <span key={k} className="mr-3">
                            {k}: <span className="text-slate-800 font-semibold">{String(v)}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DDE Execution Links */}
          {ddeFindings.length > 0 && (
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl space-y-2">
              <h4 className="font-bold text-amber-950 flex items-center gap-2">
                <span>⚡</span>
                <span>Dynamic Data Exchange (DDE) Links Detected</span>
              </h4>
              <p className="text-amber-900 text-xs">
                Document contains formulas that execute operating system commands via DDE protocols upon launch.
              </p>
              {ddeFindings.map((df, idx) => (
                <div key={idx} className="p-2.5 bg-white rounded-xl border border-amber-300 font-mono text-xs text-amber-900">
                  {df.title}: {df.description}
                </div>
              ))}
            </div>
          )}

          {/* Excel 4.0 / XLM Macros */}
          {xlmFindings.length > 0 && (
            <div className="p-4 bg-purple-50 border border-purple-200 rounded-2xl space-y-2">
              <h4 className="font-bold text-purple-950 flex items-center gap-2">
                <span>📊</span>
                <span>Excel 4.0 (XLM) Macro Sheet Detected</span>
              </h4>
              <p className="text-purple-900 text-xs">
                Legacy XLM macros execute without standard VBA runtime inspection, commonly leveraged to bypass email gateways.
              </p>
              {xlmFindings.map((xf, idx) => (
                <div key={idx} className="p-2.5 bg-white rounded-xl border border-purple-300 font-mono text-xs text-purple-900">
                  {xf.title}: {xf.description}
                </div>
              ))}
            </div>
          )}

          {/* ActiveX & OLE Object Grids */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <h4 className="font-bold text-slate-800">ActiveX Controls ({activex_objects.length})</h4>
              {activex_objects.length === 0 ? (
                <p className="text-slate-400">No ActiveX form controls found.</p>
              ) : (
                <ul className="space-y-1 font-mono text-[11px]">
                  {activex_objects.map((obj, i) => (
                    <li key={i} className="p-1.5 bg-white border border-slate-200 rounded-lg text-slate-700">{obj}</li>
                  ))}
                </ul>
              )}
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <h4 className="font-bold text-slate-800">Embedded OLE Objects ({ole_objects.length})</h4>
              {ole_objects.length === 0 ? (
                <p className="text-slate-400">No external OLE package streams found.</p>
              ) : (
                <ul className="space-y-1 font-mono text-[11px]">
                  {ole_objects.map((obj, i) => (
                    <li key={i} className="p-1.5 bg-white border border-slate-200 rounded-lg text-slate-700">{obj}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: Remote Templates & External Relationships */}
      {activeSubTab === 'relationships' && (
        <div className="space-y-4 text-xs">
          <div className="p-4 bg-amber-50/50 border border-amber-200 rounded-2xl space-y-2">
            <h4 className="font-bold text-amber-950 flex items-center gap-2">
              <Globe className="w-4 h-4 text-amber-600" />
              <span>Remote Template Injection (Follina / CVE-2022-30190 Vector)</span>
            </h4>
            <p className="text-amber-900 leading-relaxed">
              Office documents can load dynamic external templates over HTTP/HTTPS when opened. Attackers use this to bypass
              macro perimeter inspections by retrieving weapons-grade macro templates or HTML exploits only during end-user execution.
            </p>
          </div>

          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-slate-700">
              Discovered Remote Targets ({remote_templates.length + urls.length})
            </div>
            <div className="divide-y divide-slate-100 font-mono text-xs">
              {remote_templates.map((tpl, i) => {
                const target = typeof tpl === 'string' ? tpl : tpl?.target || 'Unknown Target';
                const source = typeof tpl === 'object' ? tpl?.source : null;
                const relType = typeof tpl === 'object' ? tpl?.type : null;
                const matchedJob = (() => {
                  if (!workspaceJobs || workspaceJobs.length === 0) return null;
                  return findReferencedJob(target, workspaceJobs);
                })();

                return (
                  <div key={`tpl-${i}`} className="p-3 flex items-center justify-between hover:bg-slate-50 gap-2">
                    <div className="min-w-0">
                      {matchedJob ? (
                        <button
                          type="button"
                          onClick={() => onSelectJob && onSelectJob(matchedJob.jobId)}
                          className="text-rose-600 hover:text-rose-800 font-semibold truncate hover:underline flex items-center gap-1.5 cursor-pointer text-left"
                          title={`Click to open analyzed file '${matchedJob.filename}'`}
                        >
                          <span className="truncate">{target}</span>
                          <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-100 text-indigo-800 border border-indigo-200 font-sans">
                            Linked ({matchedJob.filename})
                          </span>
                        </button>
                      ) : (
                        <span className="text-rose-600 font-semibold block truncate" title={target}>
                          {target}
                        </span>
                      )}
                      {source && (
                        <span className="text-[10px] text-slate-500 font-sans block truncate" title={source}>
                          Source: {source} {relType ? `(${relType.split('/').pop()})` : ''}
                        </span>
                      )}
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 font-sans shrink-0">
                      Template Target
                    </span>
                  </div>
                );
              })}
              {urls.map((u, i) => {
                const matchedJob = (() => {
                  if (!workspaceJobs || workspaceJobs.length === 0) return null;
                  return findReferencedJob(u, workspaceJobs);
                })();

                return (
                  <div key={`u-${i}`} className="p-3 flex items-center justify-between hover:bg-slate-50">
                    {matchedJob ? (
                      <button
                        type="button"
                        onClick={() => onSelectJob && onSelectJob(matchedJob.jobId)}
                        className="text-slate-800 hover:text-indigo-600 truncate mr-2 hover:underline flex items-center gap-1.5 cursor-pointer font-semibold text-left"
                        title={`Click to open analyzed file '${matchedJob.filename}'`}
                      >
                        <span className="truncate">{u}</span>
                        <ExternalLink className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-100 text-indigo-800 border border-indigo-200 font-sans">
                          Linked ({matchedJob.filename})
                        </span>
                      </button>
                    ) : (
                      <span className="text-slate-800 truncate mr-2">{u}</span>
                    )}
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-600 font-sans shrink-0">
                      Relationship URL
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Tab 6: Excel Sheets & Power Query M-Code */}
      {activeSubTab === 'excel' && (
        <div className="space-y-5 text-xs">
          {/* Very Hidden Sheets Warning */}
          {excelAnalysis?.very_hidden_sheets && excelAnalysis.very_hidden_sheets.length > 0 ? (
            <div className="p-4 bg-purple-50 border border-purple-300 rounded-2xl space-y-2">
              <div className="flex items-start gap-3">
                <div className="p-2 bg-purple-600 text-white rounded-xl shrink-0 mt-0.5">
                  <EyeOff className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-purple-950">
                    Excel 'Very Hidden' Sheets Detected ({excelAnalysis.very_hidden_sheets.length})
                  </h4>
                  <p className="text-purple-800 leading-relaxed mt-0.5">
                    This workbook contains worksheets with <code className="bg-purple-100 px-1.5 py-0.5 rounded text-purple-900 font-mono">state="veryHidden"</code> (<span className="font-semibold">xlSheetVeryHidden</span>). Unlike regular hidden sheets, very hidden sheets cannot be unhidden or viewed through Microsoft Excel's graphical interface. Attackers use very hidden sheets to conceal secondary stages, configuration strings, and staging payloads from users and defenders.
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl text-slate-600 flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>No 'Very Hidden' (xlSheetVeryHidden) sheets detected in workbook structure.</span>
            </div>
          )}

          {/* All Sheets Table */}
          {excelAnalysis?.all_sheets && excelAnalysis.all_sheets.length > 0 && (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
              <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
                <span>Workbook Sheets ({excelAnalysis.all_sheets.length})</span>
                <span className="text-[11px] font-normal text-slate-500 font-mono">xl/workbook.xml</span>
              </div>
              <div className="divide-y divide-slate-100">
                {excelAnalysis.all_sheets.map((sheet, idx) => {
                  const isVeryHidden = sheet.state === 'veryHidden';
                  const isHidden = sheet.state === 'hidden';
                  return (
                    <div key={idx} className="p-3 flex items-center justify-between hover:bg-slate-50">
                      <div className="flex items-center gap-2.5">
                        <Table className={`w-4 h-4 ${isVeryHidden ? 'text-purple-600' : isHidden ? 'text-amber-500' : 'text-slate-400'}`} />
                        <div>
                          <strong className="text-slate-800 text-xs block">{sheet.name}</strong>
                          <span className="text-[10px] text-slate-400 font-mono">Sheet ID: {sheet.sheet_id}</span>
                        </div>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                        isVeryHidden
                          ? 'bg-purple-100 text-purple-800 border border-purple-300'
                          : isHidden
                          ? 'bg-amber-100 text-amber-800 border border-amber-300'
                          : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}>
                        {sheet.state}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Power Query M-Code Exfiltration */}
          {excelAnalysis?.power_query_queries && excelAnalysis.power_query_queries.length > 0 ? (
            <div className="p-4 bg-rose-50 border border-rose-300 rounded-2xl space-y-3">
              <div className="flex items-start gap-3">
                <div className="p-2 bg-rose-600 text-white rounded-xl shrink-0 mt-0.5">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-rose-950">
                    Power Query (M-Code) Outbound Web &amp; Exfiltration Primitives ({excelAnalysis.power_query_queries.length})
                  </h4>
                  <p className="text-rose-800 leading-relaxed mt-0.5">
                    Excel Power Query formulas support native HTTP requests (<code className="font-mono bg-rose-100 px-1 py-0.5 rounded text-rose-900">Web.Contents()</code>, <code className="font-mono bg-rose-100 px-1 py-0.5 rounded text-rose-900">Web.Page()</code>). Threat actors abuse Power Query to bypass standard macro execution policies, exfiltrate data via HTTP headers/parameters, and stage payloads into worksheet cells without triggering VBA Antivirus alerts.
                  </p>
                </div>
              </div>

              <div className="space-y-2 pt-1">
                {excelAnalysis.power_query_queries.map((pq, idx) => (
                  <div key={idx} className="p-3 bg-white rounded-xl border border-rose-200 space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono font-semibold text-rose-900">{pq.source}</span>
                      <span className="text-[10px] font-mono bg-rose-100 text-rose-800 px-2 py-0.5 rounded font-bold">
                        {pq.matched_patterns?.join(', ') || 'Web.Contents'}
                      </span>
                    </div>
                    {pq.snippet && (
                      <pre className="p-2 bg-slate-900 text-rose-300 rounded-lg font-mono text-[11px] overflow-x-auto whitespace-pre-wrap max-h-36">
                        {pq.snippet}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl text-slate-600 flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>No Power Query M-code outbound exfiltration patterns detected.</span>
            </div>
          )}

          {/* Worksheet Protection & Hidden Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block flex items-center gap-1">
                <Lock className="w-3.5 h-3.5 text-slate-500" />
                Protected Worksheets
              </span>
              <div className="text-sm font-bold text-slate-800">
                {excelAnalysis?.protected_sheets?.length || 0} sheets
              </div>
              {excelAnalysis?.protected_sheets && excelAnalysis.protected_sheets.length > 0 && (
                <div className="text-[10px] text-slate-500 font-mono">
                  {excelAnalysis.protected_sheets.join(', ')}
                </div>
              )}
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
                Hidden Rows / Columns
              </span>
              <div className="text-sm font-bold text-slate-800">
                {excelAnalysis?.hidden_rows_cols || 0} hidden elements
              </div>
              <p className="text-[10px] text-slate-400">
                Threat actors hide rows/columns to mask staged payloads and formula scripts from view.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 7: PowerPoint Mouse-Over Action Traps */}
      {activeSubTab === 'powerpoint' && (
        <div className="space-y-5 text-xs">
          {powerpointAnalysis?.hover_actions && powerpointAnalysis.hover_actions.length > 0 ? (
            <div className="p-4 bg-rose-50 border border-rose-300 rounded-2xl space-y-3">
              <div className="flex items-start gap-3">
                <div className="p-2 bg-rose-600 text-white rounded-xl shrink-0 mt-0.5">
                  <MousePointer className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-rose-950">
                    PowerPoint Mouse-Over Action Trap Detected ({powerpointAnalysis.hover_actions.length})
                  </h4>
                  <p className="text-rose-800 leading-relaxed mt-0.5">
                    Slides in this presentation contain <code className="font-mono bg-rose-100 px-1 py-0.5 rounded text-rose-900">&lt;a:hlinkHover&gt;</code> action settings with <code className="font-mono bg-rose-100 px-1 py-0.5 rounded text-rose-900">action="ppaction://program"</code>. When viewed in presentation mode, merely hovering the cursor over the target element immediately triggers program execution (e.g. powershell.exe, cmd.exe) without requiring user click or VBA macro enablement.
                  </p>
                </div>
              </div>

              <div className="space-y-2 pt-1">
                {powerpointAnalysis.hover_actions.map((h, idx) => (
                  <div key={idx} className="p-3 bg-white rounded-xl border border-rose-200 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-rose-900">{h.slide}</span>
                      <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 font-mono text-[10px] font-bold">
                        {h.action}
                      </span>
                    </div>
                    {h.raw && (
                      <div className="p-2 bg-slate-900 text-rose-300 rounded-lg font-mono text-[11px] overflow-x-auto select-all">
                        {h.raw}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl text-slate-600 flex items-center gap-2">
              <Check className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>No Mouse-Over (&lt;a:hlinkHover&gt;) execution traps detected in slides.</span>
            </div>
          )}

          {/* Hidden Slides & Click Actions */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-2">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block flex items-center gap-1">
                <EyeOff className="w-3.5 h-3.5 text-slate-500" />
                Hidden Slides ({powerpointAnalysis?.hidden_slides?.length || 0})
              </span>
              {powerpointAnalysis?.hidden_slides && powerpointAnalysis.hidden_slides.length > 0 ? (
                <div className="space-y-1">
                  {powerpointAnalysis.hidden_slides.map((s, idx) => (
                    <div key={idx} className="p-2 bg-white rounded-lg border border-slate-200 font-mono text-[11px] text-slate-800">
                      {s} (show="0")
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 text-[11px]">All slides visible during presentation mode.</p>
              )}
            </div>

            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-2">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
                Total Slides Analyzed
              </span>
              <div className="text-lg font-bold text-slate-800">
                {powerpointAnalysis?.slide_count || 0} slides
              </div>
              <p className="text-[10px] text-slate-400">
                Inspected XML slide definitions, hyperlinked actions, and embedded relationship streams.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 8: Anti-Analysis & Macro Evasion */}
      {activeSubTab === 'anti_analysis' && (
        <div className="pt-2">
          <AntiAnalysisInspectorCard
            antiAnalysis={antiAnalysis}
            filename={filename}
            category="office"
          />
        </div>
      )}
    </div>
  );
};
