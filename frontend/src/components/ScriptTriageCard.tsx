import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Terminal,
  Copy,
  Check,
  Code,
  Layers,
  Globe,
  Zap
} from 'lucide-react';
import { ScriptTriageInfo, AntiAnalysisInfo } from '../types';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';

interface ScriptTriageCardProps {
  scriptTriage?: ScriptTriageInfo;
  filename?: string;
  category?: string;
  antiAnalysis?: AntiAnalysisInfo;
}

export const ScriptTriageCard: React.FC<ScriptTriageCardProps> = ({
  scriptTriage,
  filename = 'script',
  category: _category,
  antiAnalysis
}) => {
  const isHta = Boolean(
    scriptTriage?.hta_details?.is_hta ||
    scriptTriage?.script_type?.toLowerCase().includes('hta')
  );
  const [activeTab, setActiveTab] = useState<'patterns' | 'apis' | 'lines' | 'base64' | 'lolbins' | 'urls' | 'code' | 'hta' | 'anti_analysis'>(
    isHta ? 'hta' : 'patterns'
  );
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedModule, setSelectedModule] = useState<number>(0);

  if (!scriptTriage) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Terminal className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No script triage metadata available for this file.</p>
      </div>
    );
  }

  const {
    script_type,
    entropy,
    lines_count,
    characters_count,
    detected_patterns = [],
    matched_lines = [],
    b64_blocks = [],
    urls = [],
    risk_score,
    is_webshell,
    has_lolbins,
    lolbin_matches = [],
    code_modules = []
  } = scriptTriage;

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'high':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'medium':
        return 'bg-yellow-50 text-yellow-700 border-yellow-200';
      default:
        return 'bg-blue-50 text-blue-700 border-blue-200';
    }
  };

  const filteredMatchedLines = matched_lines.filter(
    (l) =>
      searchFilter === '' ||
      l.pattern.toLowerCase().includes(searchFilter.toLowerCase()) ||
      l.match.toLowerCase().includes(searchFilter.toLowerCase()) ||
      String(l.line).includes(searchFilter)
  );

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner / Script Overview */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-indigo-50 text-indigo-600 rounded-2xl shrink-0">
            <Terminal className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Script & Command-Line Triage
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                {script_type}
              </span>
              {is_webshell && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-700 border border-rose-300 animate-pulse">
                  Web Shell Detected
                </span>
              )}
              {has_lolbins && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-amber-50 text-amber-800 border border-amber-300">
                  LOLBins Invoked ({lolbin_matches.length})
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Deep static analysis across code execution cradles, encoded payloads, obfuscation, and command injection vectors.
            </p>
          </div>
        </div>

        {/* Quick Metrics */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 text-center min-w-[90px]">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">Risk Score</span>
            <span className={`text-base font-bold font-mono ${risk_score >= 70 ? 'text-rose-600' : risk_score >= 40 ? 'text-amber-600' : 'text-emerald-600'}`}>
              {risk_score}/100
            </span>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 text-center min-w-[90px]">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">Entropy</span>
            <span className={`text-base font-bold font-mono ${entropy >= 6.0 ? 'text-rose-600' : 'text-slate-700'}`}>
              {entropy.toFixed(2)}/8
            </span>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 text-center min-w-[90px]">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">Lines</span>
            <span className="text-base font-bold font-mono text-slate-700">
              {lines_count}
            </span>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-xl px-3.5 py-2 text-center min-w-[90px]">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">Size</span>
            <span className="text-base font-bold font-mono text-slate-700">
              {characters_count} B
            </span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-100 pb-3 overflow-x-auto scrollbar-thin">
        <button
          onClick={() => setActiveTab('patterns')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'patterns'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Suspicious Patterns ({detected_patterns.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('apis')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'apis'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Zap className="w-3.5 h-3.5 text-amber-500" />
          <span>Dangerous APIs ({(scriptTriage.dangerous_apis || []).length})</span>
        </button>

        <button
          onClick={() => setActiveTab('lines')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'lines'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Matched Lines ({matched_lines.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('base64')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeTab === 'base64'
              ? 'bg-indigo-600 text-white shadow-xs'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Base64 Chunks ({b64_blocks.length})</span>
        </button>

        {lolbin_matches.length > 0 && (
          <button
            onClick={() => setActiveTab('lolbins')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'lolbins'
                ? 'bg-indigo-600 text-white shadow-xs'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>LOLBins ({lolbin_matches.length})</span>
          </button>
        )}

        {urls.length > 0 && (
          <button
            onClick={() => setActiveTab('urls')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'urls'
                ? 'bg-indigo-600 text-white shadow-xs'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Extracted URLs ({urls.length})</span>
          </button>
        )}

        {code_modules.length > 0 && (
          <button
            onClick={() => setActiveTab('code')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'code'
                ? 'bg-indigo-600 text-white shadow-xs'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>Code Viewer</span>
          </button>
        )}

        {isHta && (
          <button
            onClick={() => setActiveTab('hta')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'hta'
                ? 'bg-purple-600 text-white shadow-xs font-bold'
                : 'text-purple-700 bg-purple-50 hover:bg-purple-100'
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-amber-400" />
            <span>HTA Deep Inspector (HTML/CSS/VBS/JS)</span>
          </button>
        )}

        <button
          onClick={() => setActiveTab('anti_analysis')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'anti_analysis'
              ? 'bg-rose-600 text-white shadow-xs font-bold'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
          <span>Anti-Analysis & Guardrails</span>
          {Boolean(antiAnalysis?.techniques && antiAnalysis.techniques.length > 0) && (
            <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold">
              {antiAnalysis?.techniques.length}
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Suspicious Patterns */}
      {activeTab === 'patterns' && (
        <div className="space-y-3">
          {detected_patterns.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs">
              No known suspicious patterns or execution cradles detected in this script.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {detected_patterns.map((pat, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-xs text-slate-900">
                      {pat.name}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-semibold uppercase ${getSeverityBadge(pat.severity)}`}>
                      {pat.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600">
                    {pat.description}
                  </p>
                  <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1">
                    <span>Sample lines: <span className="font-mono text-indigo-600">{pat.sample_lines?.join(', ') || 'N/A'}</span></span>
                    <span>Hits: <strong className="text-slate-700 font-mono">{pat.count}</strong></span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab: Categorized Dangerous APIs & Functions */}
      {activeTab === 'apis' && (
        <div className="space-y-4">
          {(!scriptTriage.dangerous_apis || scriptTriage.dangerous_apis.length === 0) ? (
            <div className="p-8 text-center text-slate-400 bg-slate-50 border border-slate-200 rounded-2xl text-xs">
              No high-risk categorized APIs or system execution calls detected.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700 flex items-center justify-between">
                <span>Categorized Dangerous Functions &amp; System Calls</span>
                <span className="text-[11px] font-mono text-slate-500 font-normal">
                  {scriptTriage.dangerous_apis.length} categories flagged
                </span>
              </div>
              <div className="divide-y divide-slate-100 text-xs">
                {scriptTriage.dangerous_apis.map((api, idx) => (
                  <div key={idx} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-50/80 transition-colors">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900">{api.category}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase ${getSeverityBadge(api.severity)}`}>
                          {api.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-100 text-slate-700 border border-slate-200">
                          {api.count} occurrence{api.count > 1 ? 's' : ''}
                        </span>
                      </div>
                      <p className="text-slate-600 text-[11px]">{api.description}</p>
                      <div className="flex items-center gap-2 pt-0.5 font-mono text-[11px]">
                        <span className="text-slate-400">Match:</span>
                        <code className="text-indigo-600 bg-indigo-50/70 px-1.5 py-0.5 rounded border border-indigo-200 font-bold">
                          {api.matched_sample}
                        </code>
                        {api.lines && api.lines.length > 0 && (
                          <span className="text-slate-500">
                            (Line{api.lines.length > 1 ? 's' : ''} {api.lines.join(', ')})
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Matched Lines */}
      {activeTab === 'lines' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <input
              type="text"
              placeholder="Filter by pattern, line number, or snippet..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="text-xs px-3 py-1.5 rounded-lg border border-slate-200 bg-white text-slate-800 placeholder-slate-400 w-full max-w-sm focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
            <span className="text-xs text-slate-400 font-mono">
              Showing {filteredMatchedLines.length} of {matched_lines.length}
            </span>
          </div>

          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white font-mono text-xs text-slate-800 max-h-96 overflow-y-auto">
            {filteredMatchedLines.length === 0 ? (
              <div className="p-6 text-center text-slate-400">No matching lines found.</div>
            ) : (
              filteredMatchedLines.map((ml, idx) => (
                <div
                  key={idx}
                  className="p-2.5 border-b border-slate-100 hover:bg-slate-50 transition-colors flex items-start gap-3"
                >
                  <span className="text-slate-400 text-[11px] w-12 shrink-0 text-right select-none font-bold">
                    L{ml.line}
                  </span>
                  <div className="flex-1 overflow-x-auto">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold uppercase ${getSeverityBadge(ml.severity)}`}>
                        {ml.severity}
                      </span>
                      <span className="text-[11px] text-indigo-600 font-medium">
                        [{ml.pattern}]
                      </span>
                    </div>
                    <code className="text-slate-800 whitespace-pre-wrap break-all text-[11px]">
                      {ml.match}
                    </code>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Base64 Decoded Blocks */}
      {activeTab === 'base64' && (
        <div className="space-y-4">
          {b64_blocks.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs">
              No continuous Base64-encoded payload blocks detected.
            </div>
          ) : (
            <div className="space-y-3">
              {b64_blocks.map((block, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-2.5"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-900 flex items-center gap-2">
                      <span>Base64 Block #{idx + 1}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-mono border border-indigo-200">
                        {block.length} bytes encoded
                      </span>
                    </span>
                    <button
                      onClick={() => copyToClipboard(block.decoded_preview, idx)}
                      className="text-xs px-2.5 py-1 rounded bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
                    >
                      {copiedIndex === idx ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-600">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-slate-500" />
                          <span>Copy Decoded</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                      Decoded Content Preview:
                    </span>
                    <pre className="p-3 bg-white text-slate-800 rounded-xl text-xs font-mono overflow-x-auto whitespace-pre-wrap max-h-48 border border-slate-200">
                      {block.decoded_preview}
                    </pre>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                      Raw Encoded Block:
                    </span>
                    <code className="text-[10px] text-slate-500 font-mono break-all line-clamp-2 block bg-white p-2 rounded-lg border border-slate-200">
                      {block.encoded}
                    </code>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 4: LOLBins */}
      {activeTab === 'lolbins' && (
        <div className="space-y-3">
          <p className="text-xs text-slate-500">
            Identified Living-off-the-Land Binaries (LOLBins) or native OS management utilities invoked within the script for defense evasion or proxy execution:
          </p>
          <div className="flex flex-wrap gap-2">
            {lolbin_matches.map((bin, idx) => (
              <span
                key={idx}
                className="px-3 py-1.5 rounded-lg border border-amber-200 bg-amber-50 text-amber-900 font-mono text-xs font-semibold flex items-center gap-2"
              >
                <Terminal className="w-3.5 h-3.5 text-amber-600" />
                {bin}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Tab 5: Extracted URLs */}
      {activeTab === 'urls' && (
        <div className="space-y-3">
          <div className="border border-slate-200 rounded-xl divide-y divide-slate-100 overflow-hidden bg-white">
            {urls.map((u, idx) => (
              <div key={idx} className="p-3 bg-white hover:bg-slate-50 transition-colors flex items-center justify-between text-xs gap-3">
                <span className="font-mono text-indigo-600 break-all select-all">
                  {u}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-medium shrink-0">
                  Defanged
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 6: Code Viewer */}
      {activeTab === 'code' && code_modules.length > 0 && (
        <div className="space-y-3">
          {code_modules.length > 1 && (
            <div className="flex items-center gap-2 mb-2">
              {code_modules.map((m, idx) => (
                <button
                  key={idx}
                  onClick={() => setSelectedModule(idx)}
                  className={`text-xs px-3 py-1 rounded-md font-medium transition-colors ${
                    selectedModule === idx
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  {m.name}
                </button>
              ))}
            </div>
          )}

          <div className="relative border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-xs">
            {/* Code Header Bar */}
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200 bg-slate-50 text-xs">
              <div className="flex items-center gap-2">
                <Code className="w-4 h-4 text-indigo-600" />
                <span className="font-mono font-bold text-slate-800">
                  {code_modules[selectedModule]?.name || filename}
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-200/70 text-slate-600 font-mono">
                  {(code_modules[selectedModule]?.code || '').split('\n').length} lines
                </span>
              </div>
              <button
                onClick={() => copyToClipboard(code_modules[selectedModule]?.code || '', 9999)}
                className="text-xs text-slate-600 hover:text-slate-900 flex items-center gap-1.5 cursor-pointer font-semibold px-2.5 py-1 rounded-lg bg-white border border-slate-200 hover:bg-slate-100 transition-colors shadow-2xs"
              >
                {copiedIndex === 9999 ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedIndex === 9999 ? 'Copied' : 'Copy Code'}</span>
              </button>
            </div>

            {/* Code Body with Row Numbers and Syntax Highlighting */}
            <div className="flex max-h-[550px] overflow-y-auto font-mono text-xs leading-5 bg-white divide-x divide-slate-100">
              {/* Row Numbers Gutter */}
              <div className="bg-slate-50 py-3 px-3 select-none text-right font-mono min-w-[50px] text-slate-400 border-r border-slate-200 space-y-0.5">
                {(code_modules[selectedModule]?.code || '').split('\n').map((_, i) => (
                  <div key={i} className="text-[11px] leading-5 text-slate-400">
                    {i + 1}
                  </div>
                ))}
              </div>

              {/* Highlighted Code Lines */}
              <div className="p-3 text-slate-800 overflow-x-auto flex-1 font-mono space-y-0.5">
                {(code_modules[selectedModule]?.code || '').split('\n').map((line, i) => {
                  const isComment = /^\s*(#|\/\/|--|rem\b|')/i.test(line);
                  if (isComment) {
                    return (
                      <div key={i} className="text-[11px] leading-5 whitespace-pre text-emerald-600 italic hover:bg-slate-50">
                        {line || ' '}
                      </div>
                    );
                  }
                  // Tokenize keywords, strings, and numbers
                  const tokens = line.split(/(\b(?:function|def|var|let|const|if|else|elif|return|import|from|require|class|echo|Set|Dim|as|for|while|foreach|try|catch|finally|throw|new|sub|end|then|select|case|goto|exit)\b|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b\d+\b)/g);
                  return (
                    <div key={i} className="text-[11px] leading-5 whitespace-pre hover:bg-slate-50">
                      {tokens.map((token, tIdx) => {
                        if (/^"(?:\\.|[^"\\])*"$|^'(?:\\.|[^'\\])*'$/.test(token)) {
                          return <span key={tIdx} className="text-amber-600 font-medium">{token}</span>;
                        }
                        if (/^\b(?:function|def|var|let|const|if|else|elif|return|import|from|require|class|echo|Set|Dim|as|for|while|foreach|try|catch|finally|throw|new|sub|end|then|select|case|goto|exit)\b$/i.test(token)) {
                          return <span key={tIdx} className="text-indigo-600 font-bold">{token}</span>;
                        }
                        if (/^\b\d+\b$/.test(token)) {
                          return <span key={tIdx} className="text-purple-600">{token}</span>;
                        }
                        return <span key={tIdx}>{token}</span>;
                      })}
                      {line === '' && ' '}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 8: HTA Deep Inspector */}
      {activeTab === 'hta' && (() => {
        const hta = scriptTriage.hta_details;
        if (!hta) {
          return (
            <div className="py-8 text-center text-slate-400 text-xs">
              No HTML Application (HTA) structured data available.
            </div>
          );
        }

        return (
          <div className="space-y-5 pt-2">
            {/* HTA Header & Stealth Mode Banner */}
            <div className="p-4 bg-purple-50 border border-purple-200 rounded-2xl flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-purple-600 text-white rounded-xl shadow-2xs">
                  <Layers className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="font-bold text-sm text-purple-950">HTML Application (HTA) Architecture</h4>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-white text-purple-700 border border-purple-200 shadow-2xs">
                      {hta.windowstate?.toUpperCase() || 'NORMAL'}
                    </span>
                  </div>
                  <p className="text-xs text-purple-800/80 mt-0.5">
                    Analyzed as composite container executing HTML layout, CSS styling, VBScript routines, and JavaScript engines.
                  </p>
                </div>
              </div>

              {hta.is_stealth_window ? (
                <span className="px-3 py-1.5 rounded-xl bg-rose-100 text-rose-800 border border-rose-300 font-bold text-xs flex items-center gap-1.5 animate-pulse">
                  <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                  Stealth WindowState Execution (Hidden / Minimized)
                </span>
              ) : (
                <span className="px-3 py-1.5 rounded-xl bg-white border border-purple-200 text-purple-800 font-medium text-xs">
                  Standard Window Display
                </span>
              )}
            </div>

            {/* Metrics Overview Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block mb-1">
                  VBScript Blocks
                </span>
                <span className="text-sm font-bold text-slate-900">
                  {hta.script_blocks?.vbscript_count || 0} routines
                </span>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block mb-1">
                  JavaScript Blocks
                </span>
                <span className="text-sm font-bold text-slate-900">
                  {hta.script_blocks?.javascript_count || 0} routines
                </span>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block mb-1">
                  Inline Event Handlers
                </span>
                <span className="text-sm font-bold text-slate-900">
                  {hta.script_blocks?.inline_handlers_count || 0} triggers
                </span>
              </div>

              <div className={`p-3 rounded-2xl border ${hta.css_analysis?.has_hidden_elements ? 'bg-rose-50 border-rose-200 text-rose-900' : 'bg-slate-50 border-slate-200 text-slate-900'}`}>
                <span className="text-[10px] uppercase font-bold tracking-wider block mb-1 text-slate-400">
                  CSS Evasion / Cloaking
                </span>
                <span className="text-sm font-bold flex items-center gap-1.5">
                  {hta.css_analysis?.has_hidden_elements ? '⚠️ Cloaked Elements' : '✓ Standard Styling'}
                </span>
              </div>
            </div>

            {/* Application Tag Properties */}
            {hta.application_tag && Object.keys(hta.application_tag).length > 0 && (
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <h5 className="font-bold text-xs text-slate-800 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-purple-600" />
                  <span>&lt;hta:application&gt; Attributes</span>
                </h5>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  {Object.entries(hta.application_tag).map(([k, v]) => (
                    <div key={k} className="p-2 bg-white rounded-xl border border-slate-200/80">
                      <span className="text-[10px] text-slate-400 uppercase block font-sans">{k}</span>
                      <span className="font-bold text-slate-800 break-all">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* CSS Cloaking & Hidden Techniques */}
            {hta.css_analysis?.hidden_techniques && hta.css_analysis.hidden_techniques.length > 0 && (
              <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl">
                <h5 className="font-bold text-xs text-rose-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                  <span>Stealth CSS Cloaking Techniques Detected</span>
                </h5>
                <div className="flex flex-wrap gap-2">
                  {hta.css_analysis.hidden_techniques.map((tech: string, i: number) => (
                    <span key={i} className="px-2.5 py-1 bg-white border border-rose-300 text-rose-800 rounded-lg text-xs font-mono font-semibold">
                      ⚠️ {tech}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* ActiveX Objects & LOLBins */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <h5 className="font-bold text-xs text-slate-800 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Zap className="w-4 h-4 text-amber-500" />
                  <span>Instantiated ActiveX Classes ({hta.activex_objects?.length || 0})</span>
                </h5>
                {hta.activex_objects && hta.activex_objects.length > 0 ? (
                  <div className="space-y-1.5">
                    {hta.activex_objects.map((cls: string, i: number) => (
                      <div key={i} className="p-2 bg-white rounded-xl border border-slate-200 text-xs font-mono font-bold text-rose-700 flex items-center justify-between">
                        <span>{cls}</span>
                        <span className="text-[10px] font-sans px-2 py-0.5 rounded-full bg-rose-50 border border-rose-200">ActiveX</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 italic">No explicit ActiveX classes detected.</p>
                )}
              </div>

              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <h5 className="font-bold text-xs text-slate-800 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-indigo-500" />
                  <span>LOLBins & Process Invocations ({hta.lolbins_invoked?.length || 0})</span>
                </h5>
                {hta.lolbins_invoked && hta.lolbins_invoked.length > 0 ? (
                  <div className="space-y-1.5">
                    {hta.lolbins_invoked.map((bin: string, i: number) => (
                      <div key={i} className="p-2 bg-white rounded-xl border border-slate-200 text-xs font-mono font-bold text-indigo-700 flex items-center justify-between">
                        <span>{bin}</span>
                        <span className="text-[10px] font-sans px-2 py-0.5 rounded-full bg-indigo-50 border border-indigo-200">LOLBin</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 italic">No common LOLBin commands detected.</p>
                )}
              </div>
            </div>

            {/* Inline Event Handlers */}
            {hta.script_blocks?.inline_handlers && hta.script_blocks.inline_handlers.length > 0 && (
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <h5 className="font-bold text-xs text-slate-800 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                  <span>Inline HTML Event Handlers ({hta.script_blocks.inline_handlers.length})</span>
                </h5>
                <div className="space-y-1.5">
                  {hta.script_blocks.inline_handlers.map((h: any, i: number) => (
                    <div key={i} className="p-2 bg-white rounded-xl border border-slate-200 text-xs font-mono flex items-start gap-2">
                      <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 font-bold shrink-0">
                        {h.event}
                      </span>
                      <span className="text-slate-700 break-all">{h.handler}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* Tab 9: Anti-Analysis, Evasion & Guardrails */}
      {activeTab === 'anti_analysis' && (
        <div className="pt-2">
          <AntiAnalysisInspectorCard
            antiAnalysis={antiAnalysis}
            filename={filename}
            category="script"
          />
        </div>
      )}
    </div>
  );
};
