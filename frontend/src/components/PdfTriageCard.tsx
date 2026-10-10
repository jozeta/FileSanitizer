import React, { useState } from 'react';
import {
  FileText,
  Code,
  Copy,
  Check,
  Zap,
  Layers,
  FileCode,
  PlayCircle,
  ShieldAlert
} from 'lucide-react';
import { PdfTriageInfo, Finding, AntiAnalysisInfo } from '../types';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';

interface PdfTriageCardProps {
  pdfInfo?: PdfTriageInfo;
  filename?: string;
  findings?: Finding[];
  antiAnalysis?: AntiAnalysisInfo;
}

export const PdfTriageCard: React.FC<PdfTriageCardProps> = ({
  pdfInfo,
  filename = 'document.pdf',
  findings: _findings,
  antiAnalysis
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'tokens' | 'internals' | 'javascript' | 'actions' | 'embedded' | 'anti_analysis'>('tokens');
  const [selectedStreamIdx, setSelectedStreamIdx] = useState<number>(0);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  if (!pdfInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <FileText className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No PDF triage metadata available for this file.</p>
      </div>
    );
  }

  const {
    page_count = 0,
    pdfid = {},
    pdfid_counts = {},
    obfuscated_tags = {},
    has_javascript,
    has_launch,
    has_open_action,
    embedded_files = [],
    eof_count = 1,
    incremental_updates = 0,
    javascript_streams = [],
    extracted_code
  } = pdfInfo;

  const rawCounts = {
    ...pdfid,
    ...pdfid_counts,
    ...((pdfInfo as any).pdfid_tags || {})
  };
  const standardTags = [
    'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
    '/Page', '/Encrypt', '/ObjStm', '/JS', '/JavaScript', '/AA', '/OpenAction',
    '/AcroForm', '/JBIG2Decode', '/RichMedia', '/Launch', '/EmbeddedFiles', '/XFA', '/URI'
  ];
  const mergedCounts: Record<string, number> = { ...rawCounts };
  for (const st of standardTags) {
    if (mergedCounts[st] === undefined) {
      mergedCounts[st] = 0;
    }
  }

  const pdfObjects = (pdfInfo as any).pdf_objects || [];
  const totalObjects = (pdfInfo as any).total_objects || pdfObjects.length;
  const totalStreams = (pdfInfo as any).total_streams || pdfObjects.filter((o: any) => o.is_stream).length;
  const filterCounts: Record<string, number> = (pdfInfo as any).filter_counts || {};
  const isLinearized = Boolean((pdfInfo as any).is_linearized);

  const currentStream = javascript_streams[selectedStreamIdx] || (extracted_code ? { stream_id: 1, size: extracted_code.code.length, code: extracted_code.code } : null);

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const getTagRiskBadge = (tag: string, count: number) => {
    if (count === 0) return null;
    if (tag === '/Launch' || tag === '/OpenAction' || tag === '/AA' || tag === '/JavaScript' || tag === '/JS') {
      return 'bg-rose-50 text-rose-700 border-rose-200 font-bold';
    }
    if (tag === '/EmbeddedFiles' || tag === '/AcroForm' || tag === '/XFA') {
      return 'bg-amber-50 text-amber-700 border-amber-200 font-semibold';
    }
    return 'bg-slate-100 text-slate-700 border-slate-200';
  };

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-rose-50 text-rose-600 rounded-2xl shrink-0">
            <FileText className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Adobe PDF Structural &amp; Didier Stevens PDFiD Triage
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                {filename}
              </span>
              {has_open_action && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  /OpenAction Auto-Run
                </span>
              )}
              {has_javascript && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-amber-50 text-amber-700 border border-amber-300">
                  JavaScript Embedded
                </span>
              )}
              {has_launch && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-red-600 text-white animate-pulse">
                  /Launch Process Execution
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Didier Stevens PDFiD token counting, /OpenAction auto-execution triggers, deobfuscated JavaScript streams, and incremental update forensic analysis.
            </p>
          </div>
        </div>

        {/* Quick Metrics Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Pages</span>
            <strong className="text-slate-900">{page_count}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">JS Streams</span>
            <strong className={javascript_streams.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {javascript_streams.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Updates (%%EOF)</span>
            <strong className="text-slate-900">{eof_count}</strong>
          </div>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2 overflow-x-auto text-xs font-semibold">
        <button
          onClick={() => setActiveSubTab('tokens')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'tokens'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Zap className="w-3.5 h-3.5 text-amber-500" />
          <span>Didier Stevens PDFiD Tokens</span>
        </button>

        <button
          onClick={() => setActiveSubTab('internals')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'internals'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-blue-500" />
          <span>PDF Internals &amp; Streams ({totalObjects})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('javascript')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'javascript'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Code className="w-3.5 h-3.5 text-rose-500" />
          <span>JavaScript Streams ({javascript_streams.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('actions')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'actions'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <PlayCircle className="w-3.5 h-3.5 text-blue-500" />
          <span>Auto-Execution &amp; /Launch</span>
        </button>

        <button
          onClick={() => setActiveSubTab('embedded')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'embedded'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-emerald-500" />
          <span>Embedded Files ({embedded_files.length})</span>
        </button>

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

      {/* Tab 1: Didier Stevens PDFiD Tokens */}
      {activeSubTab === 'tokens' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
            {Object.entries(mergedCounts).map(([tag, count]) => {
              const obfCount = obfuscated_tags[tag] || 0;
              const badgeClass = getTagRiskBadge(tag, count as number);
              return (
                <div
                  key={tag}
                  className={`p-3 rounded-2xl border transition-all ${
                    (count as number) > 0
                      ? 'bg-white border-slate-300 shadow-2xs'
                      : 'bg-slate-50/50 border-slate-200 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-slate-800">{tag}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${badgeClass || 'bg-slate-100 text-slate-600'}`}>
                      {count}
                    </span>
                  </div>
                  {obfCount > 0 && (
                    <div className="text-[10px] font-mono text-purple-700 bg-purple-50 px-1.5 py-0.5 rounded border border-purple-200 mt-1">
                      ⚠️ {obfCount} hex-obfuscated (#xx)
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {incremental_updates > 0 && (
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl text-xs text-amber-900 space-y-1">
              <strong className="block font-bold">Incremental Updates Detected ({incremental_updates} shadow updates)</strong>
              <p className="leading-relaxed">
                Document contains {eof_count} %%EOF terminal markers. Attackers use incremental updates (Shadow Attacks)
                to hide malicious actions, overlay signatures, or replace visible document layers without invalidating initial signatures.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Tab: PDF Internals & Object Streams */}
      {activeSubTab === 'internals' && (
        <div className="space-y-4 text-xs">
          {/* Metrics summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Total Objects</span>
              <strong className="text-sm text-slate-900">{totalObjects}</strong>
            </div>
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Data Streams</span>
              <strong className="text-sm text-blue-600">{totalStreams}</strong>
            </div>
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Linearized (Fast Web)</span>
              <strong className="text-sm text-slate-800">{isLinearized ? 'Yes' : 'No'}</strong>
            </div>
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-2xl">
              <span className="text-[10px] text-slate-400 block font-sans uppercase">Active Filters</span>
              <strong className="text-sm text-purple-600">{Object.keys(filterCounts).length}</strong>
            </div>
          </div>

          {/* Compression Filters Breakdown */}
          {Object.keys(filterCounts).length > 0 && (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold text-slate-700 font-sans mr-2">Stream Filters:</span>
              {Object.entries(filterCounts).map(([flt, count]) => (
                <span key={flt} className="px-2.5 py-1 rounded-xl text-xs font-mono font-semibold bg-white border border-slate-300 text-slate-800 flex items-center gap-1.5 shadow-2xs">
                  <span>{flt}</span>
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-100 text-slate-600 font-bold">{count}</span>
                </span>
              ))}
            </div>
          )}

          {/* Object & Stream Table */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
            <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 font-bold text-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-600" />
                <span>Object &amp; Stream Cross-Reference Table ({pdfObjects.length} objects inspected)</span>
              </div>
              <span className="text-[11px] text-slate-500 font-mono">PyMuPDF XRef Dissection</span>
            </div>
            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-slate-50 text-[11px] text-slate-500 uppercase border-b border-slate-200 sticky top-0">
                  <tr>
                    <th className="px-3.5 py-2">XRef #</th>
                    <th className="px-3.5 py-2">Object Type</th>
                    <th className="px-3.5 py-2">Container</th>
                    <th className="px-3.5 py-2">Filter</th>
                    <th className="px-3.5 py-2 text-right">Stream Size</th>
                    <th className="px-3.5 py-2">Indicators / Flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {pdfObjects.map((obj: any, idx: number) => (
                    <tr key={idx} className={obj.is_suspicious ? 'bg-rose-50/50 hover:bg-rose-50/80' : 'hover:bg-slate-50'}>
                      <td className="px-3.5 py-2 text-slate-600 font-bold">{obj.xref}</td>
                      <td className="px-3.5 py-2 text-slate-800 font-semibold">{obj.type}</td>
                      <td className="px-3.5 py-2">
                        {obj.is_stream ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-800">
                            Stream
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-600">
                            Dictionary
                          </span>
                        )}
                      </td>
                      <td className="px-3.5 py-2 text-slate-600 font-sans text-[11px]">{obj.filter}</td>
                      <td className="px-3.5 py-2 text-right font-sans">
                        {obj.size > 0 ? `${(obj.size / 1024).toFixed(1)} KB` : '-'}
                      </td>
                      <td className="px-3.5 py-2">
                        {obj.is_suspicious ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white animate-pulse">
                            ⚠️ {obj.suspicious_reason}
                          </span>
                        ) : (
                          <span className="text-slate-400 font-sans text-[11px]">Normal</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: JavaScript Streams & Code Viewer */}
      {activeSubTab === 'javascript' && (
        <div className="space-y-4">
          {javascript_streams.length === 0 && !extracted_code ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No JavaScript streams discovered in this PDF document.
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              {/* Stream Selector */}
              <div className="lg:col-span-1 space-y-1.5 border border-slate-200 rounded-2xl p-2 bg-slate-50/50">
                <span className="text-[10px] uppercase font-bold text-slate-400 px-2 block">
                  Extracted Streams ({javascript_streams.length || 1})
                </span>
                {(javascript_streams.length > 0 ? javascript_streams : [{ stream_id: 1, size: extracted_code?.code.length || 0, code: extracted_code?.code || '' }]).map((st, idx) => (
                  <button
                    key={idx}
                    onClick={() => setSelectedStreamIdx(idx)}
                    className={`w-full text-left p-2.5 rounded-xl text-xs font-mono transition-all flex items-center justify-between cursor-pointer ${
                      selectedStreamIdx === idx
                        ? 'bg-white shadow-xs text-rose-700 font-bold border border-rose-200'
                        : 'text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    <div>
                      <div>Stream #{st.stream_id}</div>
                      <div className="text-[10px] text-slate-400 font-normal">{st.size} bytes</div>
                    </div>
                    <FileCode className="w-3.5 h-3.5 shrink-0 opacity-60" />
                  </button>
                ))}
              </div>

              {/* Code Viewer */}
              <div className="lg:col-span-3 border border-slate-200 rounded-2xl overflow-hidden bg-slate-50 text-slate-800 font-mono text-xs">
                <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-800">Stream #{currentStream?.stream_id}</span>
                    <span className="text-[11px] text-slate-500">({currentStream?.size} bytes)</span>
                  </div>
                  <button
                    onClick={() => currentStream && handleCopyCode(currentStream.code)}
                    className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedCode ? 'Copied' : 'Copy JS'}</span>
                  </button>
                </div>

                <div className="p-4 max-h-[500px] overflow-y-auto space-y-0.5 bg-white">
                  {(currentStream?.code || '').split('\n').map((line, lIdx) => (
                    <div key={lIdx} className="flex hover:bg-slate-50 leading-5">
                      <span className="w-10 select-none text-slate-400 text-right pr-3 shrink-0">
                        {lIdx + 1}
                      </span>
                      <span className="whitespace-pre text-slate-800">{line || ' '}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Actions & Auto-Open */}
      {activeSubTab === 'actions' && (
        <div className="space-y-4 text-xs">
          <div className="p-4 bg-rose-50/50 border border-rose-200 rounded-2xl space-y-2">
            <h4 className="font-bold text-rose-950 flex items-center gap-2">
              <PlayCircle className="w-4 h-4 text-rose-600" />
              <span>Automatic Execution Hooks (/OpenAction &amp; /AA)</span>
            </h4>
            <p className="text-rose-900 leading-relaxed">
              PDF files support auto-executing scripts or launching applications upon document open, page transition, or bookmark click.
              Malicious documents leverage /OpenAction and /AA to detonate payloads without requiring user interaction.
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                has_open_action ? 'bg-rose-600 text-white animate-pulse' : 'bg-slate-100 text-slate-700'
              }`}>
                {has_open_action ? '⚠️ /OpenAction Present' : '✓ No /OpenAction'}
              </span>
              <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${
                has_launch ? 'bg-rose-600 text-white animate-pulse' : 'bg-slate-100 text-slate-700'
              }`}>
                {has_launch ? '⚠️ /Launch Present (RCE Vector)' : '✓ No /Launch'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Embedded Files */}
      {activeSubTab === 'embedded' && (
        <div className="space-y-4 text-xs">
          {embedded_files.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No embedded files or attachments found inside this PDF.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-slate-700">
                Embedded Attachments (/EmbeddedFiles)
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {embedded_files.map((f, i) => (
                  <div key={i} className="p-3 flex items-center justify-between hover:bg-slate-50">
                    <span className="text-slate-800 font-semibold">{f}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 font-sans">
                      Attachment
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 6: Anti-Analysis & PDF Evasion */}
      {activeSubTab === 'anti_analysis' && (
        <div className="pt-2">
          <AntiAnalysisInspectorCard
            antiAnalysis={antiAnalysis}
            filename={filename}
            category="pdf"
          />
        </div>
      )}
    </div>
  );
};
