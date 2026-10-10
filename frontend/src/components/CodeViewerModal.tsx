import React, { useState } from 'react';
import { ExtractedCode } from '../types';

interface CodeViewerModalProps {
  isOpen: boolean;
  onClose: () => void;
  extractedCode?: ExtractedCode | null;
  sourceFilename: string;
}

export const CodeViewerModal: React.FC<CodeViewerModalProps> = ({
  isOpen,
  onClose,
  extractedCode,
  sourceFilename,
}) => {
  const [selectedModuleIndex, setSelectedModuleIndex] = useState<number>(-1); // -1 means all combined
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  if (!isOpen) return null;

  const safeCode = extractedCode || {
    type: 'vba',
    language: 'vb',
    code: "' Macro indicators were identified in document relationships and structures.\n' Raw decompiled VBA stream was protected, obfuscated, or in legacy format.\n' Refer to the Macro Warning Banner and Finding Catalog for specific detected triggers.",
    modules: []
  };

  const modules = safeCode.modules || [];
  const currentCode =
    selectedModuleIndex === -1
      ? safeCode.code
      : modules[selectedModuleIndex]?.code || '';

  const handleCopy = () => {
    navigator.clipboard.writeText(currentCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const ext = safeCode.type === 'vba' ? 'vba' : 'js';
    const blob = new Blob([currentCode], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${sourceFilename}_extracted_code.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Syntax highlighting parser
  const renderHighlightedCode = (rawCode: string) => {
    const lines = rawCode.split('\n');
    return lines.map((line, idx) => {
      const lineNum = idx + 1;
      const isSearchMatch =
        searchQuery.trim().length > 1 &&
        line.toLowerCase().includes(searchQuery.toLowerCase());

      return (
        <div
          key={idx}
          className={`flex hover:bg-slate-50 font-mono text-xs leading-5 transition-colors ${
            isSearchMatch ? 'bg-amber-100 border-l-2 border-amber-500' : ''
          }`}
        >
          <span className="w-12 pr-4 text-right text-slate-400 select-none border-r border-slate-200 font-mono">
            {lineNum}
          </span>
          <span className="pl-4 pr-2 text-slate-800 whitespace-pre overflow-x-auto flex-1">
            {highlightLineTokens(line, safeCode.type)}
          </span>
        </div>
      );
    });
  };

  // Tokenizer for VBA / JavaScript
  const highlightLineTokens = (line: string, type: string) => {
    if (type === 'vba') {
      // Check comment first
      const commentIdx = line.indexOf("'");
      if (commentIdx !== -1) {
        const codePart = line.substring(0, commentIdx);
        const commentPart = line.substring(commentIdx);
        return (
          <>
            {highlightVbaCodeOnly(codePart)}
            <span className="text-emerald-700 italic">{commentPart}</span>
          </>
        );
      }
      return highlightVbaCodeOnly(line);
    } else {
      // JavaScript
      const commentIdx = line.indexOf('//');
      if (commentIdx !== -1) {
        const codePart = line.substring(0, commentIdx);
        const commentPart = line.substring(commentIdx);
        return (
          <>
            {highlightJsCodeOnly(codePart)}
            <span className="text-emerald-700 italic">{commentPart}</span>
          </>
        );
      }
      return highlightJsCodeOnly(line);
    }
  };

  const highlightVbaCodeOnly = (str: string) => {
    const vbaKeywords = new Set([
      'sub', 'end', 'function', 'dim', 'as', 'set', 'if', 'then', 'else', 'elseif',
      'for', 'to', 'step', 'next', 'while', 'wend', 'do', 'loop', 'select', 'case',
      'on', 'error', 'resume', 'goto', 'call', 'with', 'private', 'public', 'const',
      'true', 'false', 'nothing', 'null', 'string', 'integer', 'long', 'boolean', 'byte'
    ]);
    const vbaSuspicious = new Set([
      'wscript.shell', 'shell', 'createobject', 'powershell', 'cmd.exe', 'urldownloadtofile',
      'autoopen', 'document_open', 'workbook_open', 'environ', 'kill', 'filecopy', 'getattr'
    ]);

    // Split words, quotes, symbols
    const parts = str.split(/("[^"]*"|\b[A-Za-z0-9_.]+\b|[^\sA-Za-z0-9_."]+|\s+)/g);
    return parts.map((part, i) => {
      if (!part) return null;
      if (part.startsWith('"') && part.endsWith('"')) {
        return <span key={i} className="text-amber-800">{part}</span>;
      }
      const lower = part.toLowerCase();
      if (vbaSuspicious.has(lower)) {
        return <span key={i} className="text-rose-700 font-bold underline bg-rose-50 px-0.5 rounded border border-rose-200">{part}</span>;
      }
      if (vbaKeywords.has(lower)) {
        return <span key={i} className="text-indigo-600 font-semibold">{part}</span>;
      }
      return <span key={i}>{part}</span>;
    });
  };

  const highlightJsCodeOnly = (str: string) => {
    const jsKeywords = new Set([
      'function', 'var', 'let', 'const', 'if', 'else', 'return', 'new', 'try', 'catch',
      'finally', 'throw', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
      'class', 'import', 'export', 'default', 'true', 'false', 'null', 'undefined', 'this'
    ]);
    const jsSuspicious = new Set([
      'eval', 'unescape', 'launchurl', 'document.write', 'innerhtml', 'heap', 'shell',
      'wscript', 'activexobject', 'exec', 'payload', 'powershell', 'base64'
    ]);

    const parts = str.split(/("[^"]*"|'[^']*'|\b[A-Za-z0-9_.]+\b|[^\sA-Za-z0-9_.'"]+|\s+)/g);
    return parts.map((part, i) => {
      if (!part) return null;
      if ((part.startsWith('"') && part.endsWith('"')) || (part.startsWith("'") && part.endsWith("'"))) {
        return <span key={i} className="text-amber-800">{part}</span>;
      }
      const lower = part.toLowerCase();
      if (jsSuspicious.has(lower)) {
        return <span key={i} className="text-rose-700 font-bold underline bg-rose-50 px-0.5 rounded border border-rose-200">{part}</span>;
      }
      if (jsKeywords.has(lower)) {
        return <span key={i} className="text-indigo-600 font-semibold">{part}</span>;
      }
      return <span key={i}>{part}</span>;
    });
  };

  return (
    <div className="fixed inset-0 z-[9999] bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 animate-overlay-fade">
      <div className="relative w-full max-w-5xl bg-white border border-slate-200 rounded-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] animate-modal-fade">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-100 bg-white flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="p-2 bg-rose-50 text-rose-600 rounded-xl text-lg border border-rose-100">
              {safeCode.type === 'vba' ? '📄' : '📜'}
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-900">
                  {safeCode.type === 'vba'
                    ? 'Extracted VBA Macro Source Code'
                    : 'Extracted JavaScript Source Code'}
                </h3>
                <span className="px-2 py-0.5 text-xs font-semibold rounded uppercase tracking-wider bg-rose-50 text-rose-700 border border-rose-200">
                  {safeCode.type.toUpperCase()}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Extracted from <span className="text-slate-700 font-medium">{sourceFilename}</span> • Strictly Sandboxed Read-Only View
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium rounded-xl border border-slate-200 flex items-center gap-1.5 transition-all shadow-xs"
            >
              {copied ? '✓ Copied' : '📋 Copy Code'}
            </button>
            <button
              onClick={handleDownload}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium rounded-xl border border-slate-200 flex items-center gap-1.5 transition-all shadow-xs"
            >
              ⬇ Download
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors ml-2"
              title="Close modal"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Notice & Search Bar */}
        <div className="px-6 py-2.5 bg-rose-50 border-b border-rose-100 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-rose-800">
            <span className="font-bold">⚠️ Security Notice:</span>
            <span>Do not execute this code on your host workstation without dedicated sandbox containment.</span>
          </div>

          <div className="relative">
            <input
              type="text"
              placeholder="Search keywords, URLs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-white border border-slate-200 rounded-lg px-3 py-1 text-xs text-slate-800 placeholder-slate-400 w-56 focus:outline-none focus:border-indigo-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Module Tabs (if multiple modules exist) */}
        {modules.length > 0 && (
          <div className="flex items-center gap-1 px-6 pt-3 pb-0 bg-slate-50 border-b border-slate-200 overflow-x-auto text-xs">
            <button
              onClick={() => setSelectedModuleIndex(-1)}
              className={`px-3 py-2 font-medium rounded-t-lg transition-colors border-b-2 flex items-center gap-1.5 ${
                selectedModuleIndex === -1
                  ? 'bg-white text-indigo-600 border-indigo-600 shadow-xs'
                  : 'text-slate-500 hover:text-slate-800 border-transparent'
              }`}
            >
              <span>📑</span>
              All Modules Combined ({modules.length})
            </button>

            {modules.map((m, idx) => (
              <button
                key={idx}
                onClick={() => setSelectedModuleIndex(idx)}
                className={`px-3 py-2 font-medium rounded-t-lg transition-colors border-b-2 flex items-center gap-1.5 whitespace-nowrap ${
                  selectedModuleIndex === idx
                    ? 'bg-white text-indigo-600 border-indigo-600 shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 border-transparent'
                }`}
              >
                <span>{safeCode.type === 'vba' ? '📄' : '📜'}</span>
                {m.name}
              </button>
            ))}
          </div>
        )}

        {/* Code Content Container */}
        <div className="flex-1 p-4 overflow-y-auto bg-slate-50/50">
          <div className="rounded-2xl bg-white border border-slate-200 py-3 shadow-xs">
            {currentCode.trim() ? (
              renderHighlightedCode(currentCode)
            ) : (
              <div className="text-center py-12 text-slate-400 text-sm">
                No source code extracted for this module.
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-100 bg-white flex items-center justify-between text-xs text-slate-500">
          <div>
            <span>Language: <span className="text-slate-800 font-mono font-medium">{safeCode.language}</span></span>
            <span className="mx-2">•</span>
            <span>Total Lines: <span className="text-slate-800 font-mono font-medium">{currentCode.split('\n').length}</span></span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-xl transition-colors"
          >
            Close Viewer
          </button>
        </div>
      </div>
    </div>
  );
};
