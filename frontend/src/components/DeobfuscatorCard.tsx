import React, { useState } from 'react';
import { DeobfuscationResult } from '../types';
import { Terminal, Key, ShieldAlert, Copy, Check, Play, RefreshCw, Globe } from 'lucide-react';

interface DeobfuscatorCardProps {
  jobId: string;
  deobfuscation?: DeobfuscationResult;
  initialCode?: string;
}

export const DeobfuscatorCard: React.FC<DeobfuscatorCardProps> = ({
  jobId,
  deobfuscation,
  initialCode = ''
}) => {
  const [inputText, setInputText] = useState(initialCode);
  const [customResult, setCustomResult] = useState<DeobfuscationResult | null>(null);
  const [operationResult, setOperationResult] = useState<any>(null);
  const [activeOp, setActiveOp] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleRunDeobfuscation = async () => {
    setIsLoading(true);
    setOperationResult(null);
    setActiveOp(null);
    try {
      const resp = await fetch(`/api/jobs/${jobId}/deobfuscate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText, operation: 'analyze' })
      });
      if (resp.ok) {
        const data = await resp.json();
        setCustomResult(data);
      }
    } catch (err) {
      console.error('Deobfuscation request failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunOperation = async (op: string) => {
    if (!inputText.trim()) return;
    setIsLoading(true);
    setActiveOp(op);
    setCustomResult(null);
    try {
      const resp = await fetch(`/api/jobs/${jobId}/deobfuscate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText, operation: op })
      });
      if (resp.ok) {
        const data = await resp.json();
        setOperationResult(data);
      }
    } catch (err) {
      console.error('CyberChef operation failed:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const activeResult = customResult || deobfuscation;

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm mb-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-amber-50 text-amber-700 rounded-2xl shrink-0 border border-amber-200">
            <Terminal className="w-6 h-6" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Automated Forensic Deobfuscator & String Decoder
              </h3>
              <span className="text-xs bg-amber-100 text-amber-800 border border-amber-200 px-2.5 py-0.5 rounded-full font-mono font-semibold">
                CyberChef / XOR & Base64
              </span>
            </div>
            <p className="text-xs text-slate-500 font-normal">
              Detects and decodes single-byte XOR ciphers, recursive Base64, UTF-16LE PowerShell payloads, and reveals secondary IOCs.
            </p>
          </div>
        </div>
      </div>

      {/* Automated Findings Summary */}
      {activeResult && activeResult.has_deobfuscated_content && (
        <div className="bg-amber-50/70 border border-amber-200 rounded-2xl p-4 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs text-amber-900">
            <span className="font-bold text-amber-950 block">Deobfuscated Content Identified</span>
            <p>{activeResult.summary}</p>
          </div>
        </div>
      )}

      {/* Discovered Single-Byte XOR Keys */}
      {activeResult?.xor_candidates && activeResult.xor_candidates.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <Key className="w-4 h-4 text-amber-600" />
            <span>Single-Byte XOR Plaintext Anchors ({activeResult.xor_candidates.length} Keys Identified)</span>
          </h4>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {activeResult.xor_candidates.map((xor, idx) => (
              <div key={idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold bg-amber-100 text-amber-900 px-2.5 py-1 rounded-lg border border-amber-200">
                      Key: {xor.key_hex} ({xor.key_decimal})
                    </span>
                    <span className="text-[11px] text-slate-500 font-medium">
                      Matched: {xor.matched_anchors.join(', ')}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(xor.revealed_strings_sample, `xor-${idx}`)}
                    className="p-1.5 text-slate-500 hover:text-slate-800 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
                    title="Copy revealed text"
                  >
                    {copiedKey === `xor-${idx}` ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>

                <div className="bg-white border border-slate-200 rounded-xl p-3 font-mono text-[11px] text-slate-800 max-h-32 overflow-y-auto whitespace-pre-wrap">
                  {xor.revealed_strings_sample}
                </div>

                {xor.extracted_urls && xor.extracted_urls.length > 0 && (
                  <div className="text-[11px] text-slate-600 flex items-center gap-1.5 flex-wrap">
                    <Globe className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                    <span className="font-semibold text-slate-800">Hidden URLs:</span>
                    {xor.extracted_urls.map((u, i) => (
                      <span key={i} className="font-mono bg-indigo-50 text-indigo-700 px-1.5 py-0.5 rounded border border-indigo-100 truncate max-w-xs">
                        {u}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Discovered Base64 Blocks */}
      {activeResult?.base64_blocks && activeResult.base64_blocks.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-600" />
            <span>Decoded Base64 Blocks ({activeResult.base64_blocks.length} Blocks Extracted)</span>
          </h4>
          <div className="space-y-3">
            {activeResult.base64_blocks.map((b64, idx) => (
              <div key={idx} className="bg-slate-50 border border-slate-200 rounded-2xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold bg-indigo-50 text-indigo-800 border border-indigo-200 px-2 py-0.5 rounded-lg font-mono">
                      {b64.encoding}
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono">
                      Payload: {b64.bytes_len} bytes
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(b64.decoded, `b64-${idx}`)}
                    className="p-1.5 text-slate-500 hover:text-slate-800 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
                    title="Copy decoded text"
                  >
                    {copiedKey === `b64-${idx}` ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Encoded Block</span>
                    <div className="bg-slate-100 border border-slate-200 rounded-xl p-2.5 font-mono text-[10px] text-slate-600 truncate">
                      {b64.encoded}
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px] font-bold text-indigo-700 uppercase tracking-wider block mb-1">Decoded Output</span>
                    <div className="bg-white border border-slate-200 rounded-xl p-2.5 font-mono text-[11px] text-slate-800 max-h-24 overflow-y-auto whitespace-pre-wrap">
                      {b64.decoded}
                    </div>
                  </div>
                </div>

                {b64.extracted_urls && b64.extracted_urls.length > 0 && (
                  <div className="text-[11px] text-slate-600 flex items-center gap-1.5 flex-wrap">
                    <Globe className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                    <span className="font-semibold text-slate-800">Secondary URLs:</span>
                    {b64.extracted_urls.map((u, i) => (
                      <span key={i} className="font-mono bg-indigo-50 text-indigo-700 px-1.5 py-0.5 rounded border border-indigo-100 truncate max-w-xs">
                        {u}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Interactive Deobfuscation Workbench */}
      <div className="pt-4 border-t border-slate-100 space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <RefreshCw className="w-4 h-4 text-slate-600" />
            <span>Interactive Deobfuscator Workbench</span>
          </h4>
          <span className="text-[11px] text-slate-500">
            Paste suspicious strings, shellcode stubs, or encoded payloads
          </span>
        </div>

        <div className="space-y-2">
          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste obfuscated base64, hex stream, or XOR encrypted script text here..."
            className="w-full h-28 p-3 rounded-2xl border border-slate-200 bg-slate-50 text-slate-900 font-mono text-xs focus:bg-white focus:outline-none focus:ring-2 focus:ring-amber-500/20 focus:border-amber-500 transition-all resize-y"
          />
          {/* CyberChef Quick Actions Toolbar */}
          <div className="space-y-1.5 pt-1">
            <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider block">
              CyberChef Quick Forensic Operations:
            </span>
            <div className="flex flex-wrap gap-1.5">
              {[
                { id: 'rot13', label: 'ROT13' },
                { id: 'rot47', label: 'ROT47' },
                { id: 'caesar', label: 'Caesar Brute-Force' },
                { id: 'html', label: 'HTML Entity Decode' },
                { id: 'url', label: 'URL Double-Decode' },
                { id: 'base85', label: 'Base85 / Ascii85' },
                { id: 'reverse', label: 'Reverse String' },
                { id: 'defang', label: 'Defang IOCs' },
                { id: 'refang', label: 'Refang IOCs' },
                { id: 'ip_convert', label: 'IP Format Converter' },
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => handleRunOperation(btn.id)}
                  disabled={isLoading || !inputText.trim()}
                  className={`px-2.5 py-1 rounded-lg text-xs font-semibold border transition-all cursor-pointer disabled:opacity-40 ${
                    activeOp === btn.id
                      ? 'bg-amber-100 text-amber-900 border-amber-300 shadow-xs'
                      : 'bg-white hover:bg-slate-50 text-slate-700 border-slate-200'
                  }`}
                >
                  {btn.label}
                </button>
              ))}
            </div>
          </div>

          {/* Operation Result Box */}
          {operationResult && (
            <div className="mt-3 p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-700">
                  Operation Result: <span className="text-amber-700 font-mono">{operationResult.operation}</span>
                </span>
                <button
                  onClick={() => handleCopy(
                    typeof operationResult.result === 'object'
                      ? JSON.stringify(operationResult.result, null, 2)
                      : String(operationResult.result || JSON.stringify(operationResult.candidates, null, 2)),
                    'op_res'
                  )}
                  className="text-xs font-semibold text-slate-600 hover:text-slate-800 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'op_res' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'op_res' ? 'Copied' : 'Copy Result'}</span>
                </button>
              </div>

              {operationResult.candidates ? (
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                  {operationResult.candidates.slice(0, 10).map((c: any, i: number) => (
                    <div key={i} className="p-2 bg-white rounded border border-slate-200 font-mono text-xs flex justify-between gap-2">
                      <span className="font-bold text-amber-800 shrink-0">Shift +{c.shift}:</span>
                      <span className="text-slate-800 break-all flex-1">{c.text}</span>
                      <span className="text-slate-400 text-[10px] shrink-0 font-sans">Score: {c.score}</span>
                    </div>
                  ))}
                </div>
              ) : typeof operationResult.result === 'object' ? (
                <pre className="p-3 bg-white rounded-xl border border-slate-200 font-mono text-xs text-slate-800 whitespace-pre-wrap">
                  {JSON.stringify(operationResult.result, null, 2)}
                </pre>
              ) : (
                <pre className="p-3 bg-white rounded-xl border border-slate-200 font-mono text-xs text-slate-800 whitespace-pre-wrap break-all">
                  {operationResult.result}
                </pre>
              )}
            </div>
          )}

          <div className="flex justify-between items-center pt-2">
            <button
              onClick={() => setInputText(initialCode)}
              disabled={!initialCode}
              className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold cursor-pointer disabled:opacity-40"
            >
              Reset to Extracted Code
            </button>
            <button
              onClick={handleRunDeobfuscation}
              disabled={isLoading || !inputText.trim()}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold bg-amber-600 hover:bg-amber-700 text-white transition-all shadow-sm cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isLoading ? 'Decoding...' : 'Run Automated Scanner'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
