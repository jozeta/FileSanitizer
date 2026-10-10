import React from 'react';
import {
  Sparkles,
  ZapOff,
  FileCheck2,
  Trash2,
  AlertTriangle,
  Layers,
  Activity,
  CheckCircle2,
  Download,
} from 'lucide-react';
import { CdrDiffInfo } from '../types';

interface CdrDiffInspectorProps {
  cdrDiff?: CdrDiffInfo | null;
  onRunSanitization?: () => void;
  onDownload?: () => void;
}

export const CdrDiffInspector: React.FC<CdrDiffInspectorProps> = ({ cdrDiff, onRunSanitization, onDownload }) => {
  if (!cdrDiff) {
    return (
      <div className="bg-white border border-slate-200 rounded-3xl p-10 text-center shadow-xs">
        <div className="w-14 h-14 bg-indigo-50 border border-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-4 text-indigo-600">
          <Layers className="w-7 h-7" />
        </div>
        <h4 className="font-bold text-slate-900 text-base">Visual & Structural CDR Differencing</h4>
        <p className="text-xs text-slate-500 mt-2 max-w-lg mx-auto leading-relaxed">
          Content Disarm & Reconstruction provides deep structural diffing: side-by-side byte size reduction, Shannon entropy delta shifts, neutralized attack surfaces, pruned metadata tags, and sanitized code streams.
        </p>
        {onRunSanitization && (
          <div className="mt-6">
            <button
              type="button"
              onClick={onRunSanitization}
              className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-semibold shadow-xs transition-all inline-flex items-center gap-2 cursor-pointer"
            >
              <Sparkles className="w-4 h-4" />
              <span>Configure & Run CDR Sanitization</span>
            </button>
          </div>
        )}
      </div>
    );
  }

  const { original_file, sanitized_file, metrics, structural_modifications, actions_taken, removed_items, warnings } = cdrDiff;

  return (
    <div className="space-y-6">
      {/* Pre-Download Inspection Banner */}
      {onDownload && (
        <div className="p-4 bg-gradient-to-r from-emerald-50 to-teal-50 border border-emerald-200 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-emerald-600 text-white flex items-center justify-center font-bold">
              ✓
            </div>
            <div>
              <h5 className="font-bold text-xs text-emerald-950">Pre-Download Structural Verification</h5>
              <p className="text-[11px] text-emerald-800">
                Inspect all removed items, structural deltas, and sanitized streams below before downloading your clean file.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onDownload}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-xl shadow-xs transition-colors flex items-center gap-2 cursor-pointer shrink-0"
          >
            <Download className="w-4 h-4" />
            <span>Download Clean File</span>
          </button>
        </div>
      )}

      {/* High-Impact Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Bytes Reduced */}
        <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Size Reduction</span>
            <span className="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-bold font-mono">
              -{metrics.reduction_percentage}%
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-black text-slate-900 font-mono">
              {(metrics.bytes_reduced / 1024).toFixed(1)}
            </span>
            <span className="text-xs text-slate-500 font-medium">KB stripped</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1 truncate">
            {original_file.size_bytes.toLocaleString()} B → {sanitized_file.size_bytes.toLocaleString()} B
          </p>
        </div>

        {/* Entropy Delta */}
        <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Entropy Delta</span>
            <Activity className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-black text-slate-900 font-mono">
              {metrics.entropy_delta >= 0 ? `+${metrics.entropy_delta}` : metrics.entropy_delta}
            </span>
            <span className="text-xs text-slate-500 font-medium">Shannon / 8.0</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Original: {original_file.entropy} → Clean: {sanitized_file.entropy}
          </p>
        </div>

        {/* Threats Neutralized */}
        <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Threats Disarmed</span>
            <ZapOff className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-black text-rose-600 font-mono">
              {metrics.threats_neutralized}
            </span>
            <span className="text-xs text-slate-500 font-medium">active vectors</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            High & critical attack surfaces eliminated
          </p>
        </div>

        {/* Structural Modifications */}
        <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
            <span>Pruned Structural Nodes</span>
            <Layers className="w-4 h-4 text-sky-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-1.5">
            <span className="text-2xl font-black text-sky-600 font-mono">
              {structural_modifications.length}
            </span>
            <span className="text-xs text-slate-500 font-medium">elements</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Objects, scripts & metadata restructured
          </p>
        </div>
      </div>

      {/* Side-by-Side Comparison Matrix */}
      <div className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
        <div className="p-4 bg-slate-50/70 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-emerald-600" />
            <h4 className="text-sm font-bold text-slate-900">Side-by-Side Structural Inspection</h4>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Original Artifact vs Sanitized Reconstruction</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-200">
          {/* Before: Original */}
          <div className="p-5 bg-rose-50/20">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-rose-800 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                Original Input (Unsanitized)
              </span>
              <span className="text-[11px] font-mono text-slate-500">{original_file.size_bytes.toLocaleString()} bytes</span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-rose-100">
                <span className="text-slate-500 font-sans">Filename:</span>
                <span className="font-semibold text-slate-800 truncate max-w-[200px]">{original_file.filename}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-rose-100">
                <span className="text-slate-500 font-sans">Shannon Entropy:</span>
                <span className="font-semibold text-slate-800">{original_file.entropy} / 8.0</span>
              </div>
              <div className="flex justify-between py-1 border-b border-rose-100">
                <span className="text-slate-500 font-sans">Metadata Attributes:</span>
                <span className="font-semibold text-rose-700">{original_file.metadata_fields} fields</span>
              </div>
              <div className="flex flex-col py-1">
                <span className="text-slate-500 font-sans text-[11px]">SHA-256:</span>
                <span className="font-semibold text-slate-700 text-[10px] break-all">{original_file.sha256}</span>
              </div>
            </div>
          </div>

          {/* After: Sanitized */}
          <div className="p-5 bg-emerald-50/20">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-emerald-800 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                Sanitized Artifact (Verified Clean)
              </span>
              <span className="text-[11px] font-mono text-emerald-700 font-bold">{sanitized_file.size_bytes.toLocaleString()} bytes</span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-emerald-100">
                <span className="text-slate-500 font-sans">Filename:</span>
                <span className="font-semibold text-slate-800 truncate max-w-[200px]">{sanitized_file.filename}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-emerald-100">
                <span className="text-slate-500 font-sans">Shannon Entropy:</span>
                <span className="font-semibold text-slate-800">{sanitized_file.entropy} / 8.0</span>
              </div>
              <div className="flex justify-between py-1 border-b border-emerald-100">
                <span className="text-slate-500 font-sans">Metadata Attributes:</span>
                <span className="font-semibold text-emerald-700">{sanitized_file.metadata_fields} fields (Stripped)</span>
              </div>
              <div className="flex flex-col py-1">
                <span className="text-slate-500 font-sans text-[11px]">SHA-256:</span>
                <span className="font-semibold text-slate-700 text-[10px] break-all">{sanitized_file.sha256}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Structural Modifications Ledger */}
      {structural_modifications && structural_modifications.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
          <div className="p-4 bg-slate-50/70 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Trash2 className="w-4 h-4 text-rose-600" />
              <h4 className="text-sm font-bold text-slate-900">Structural Disarm & Neutralization Ledger</h4>
            </div>
            <span className="text-xs font-medium text-slate-500">
              {structural_modifications.length} attack surfaces neutralized
            </span>
          </div>

          <div className="divide-y divide-slate-100">
            {structural_modifications.map((mod, idx) => (
              <div key={idx} className="p-4 flex items-start justify-between gap-4 hover:bg-slate-50/50 transition-colors">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-900">{mod.element}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-semibold">
                      {mod.action}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">{mod.description}</p>
                </div>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  mod.severity === 'critical' ? 'bg-rose-100 text-rose-800' :
                  mod.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                  mod.severity === 'medium' ? 'bg-amber-100 text-amber-800' :
                  'bg-slate-100 text-slate-700'
                }`}>
                  {mod.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sanitizer Execution Actions Log */}
      {actions_taken && actions_taken.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
          <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-3 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>CDR Engine Actions Completed ({actions_taken.length})</span>
          </h4>
          <div className="space-y-2">
            {actions_taken.map((act, idx) => (
              <div key={idx} className="flex items-center gap-2 text-xs text-slate-700 bg-emerald-50/40 border border-emerald-100 px-3 py-1.5 rounded-xl">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                <span>{act}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Removed Items */}
      {removed_items && removed_items.length > 0 && (
        <div className="bg-rose-50/50 border border-rose-200 rounded-2xl p-4 text-rose-900 text-xs">
          <div className="flex items-center gap-2 font-bold mb-2">
            <Trash2 className="w-4 h-4 text-rose-600" />
            <span>Pruned & Stripped Components ({removed_items.length})</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {removed_items.map((item, idx) => (
              <span key={idx} className="px-2.5 py-1 bg-white border border-rose-200 text-rose-800 font-mono text-[11px] rounded-lg">
                {item}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Warnings / Advisories */}
      {warnings && warnings.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 text-amber-900 text-xs">
          <div className="flex items-center gap-2 font-bold mb-2">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            <span>Sanitization Advisories ({warnings.length})</span>
          </div>
          <ul className="list-disc list-inside space-y-1 text-amber-800">
            {warnings.map((w, idx) => (
              <li key={idx}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
