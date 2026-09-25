import React from 'react';
import { CheckCircle2, Download, FileText, ShieldCheck, ArrowRight, AlertTriangle } from 'lucide-react';
import { ValidationComparison as ValidationType } from '../types';
import { truncateHash, formatBytes } from '../utils/formatters';

interface ValidationComparisonProps {
  validation?: ValidationType;
  sanitizedFilename?: string;
  onDownload: () => void;
  onDownloadReport: () => void;
  warnings?: string[];
}

export const ValidationComparison: React.FC<ValidationComparisonProps> = ({
  validation,
  sanitizedFilename,
  onDownload,
  onDownloadReport,
  warnings = []
}) => {
  if (!validation) return null;

  const orig = validation.original;
  const clean = validation.sanitized;

  return (
    <div className="bg-white rounded-3xl border border-emerald-200/80 p-6 sm:p-8 shadow-sm">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-emerald-100 text-emerald-700 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-slate-900 tracking-tight">
              Post-Sanitization Verification Matrix
            </h3>
            <p className="text-xs text-slate-500 font-mono">
              Output file: {sanitizedFilename || 'sanitized_document'} · Verified clean
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onDownloadReport}
            className="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors flex items-center gap-2 cursor-pointer"
            title="Download JSON Security Audit Report"
          >
            <FileText className="w-4 h-4 text-slate-500" />
            <span>Audit Report</span>
          </button>

          <button
            onClick={onDownload}
            className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-xl shadow-sm transition-all flex items-center gap-2 cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>Download Clean File</span>
          </button>
        </div>
      </div>

      {/* Warnings / CDR Notes */}
      {warnings.length > 0 && (
        <div className="mt-5 p-4 bg-amber-50 rounded-2xl border border-amber-200/70 text-amber-900 text-xs space-y-1">
          <span className="font-bold flex items-center gap-1.5 text-amber-950">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            <span>Reconstruction & Disarm Notices:</span>
          </span>
          {warnings.map((w: string, i: number) => (
            <p key={i} className="leading-relaxed pl-5 font-normal">• {w}</p>
          ))}
        </div>
      )}

      {/* Side-by-Side Comparison Table */}
      <div className="mt-6 overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-200 text-slate-400">
              <th className="pb-3 font-normal uppercase">Security Vector</th>
              <th className="pb-3 font-normal uppercase text-slate-600">Original File</th>
              <th className="pb-3 font-normal uppercase text-center w-8"></th>
              <th className="pb-3 font-normal uppercase text-emerald-700 font-bold">Sanitized Clean File</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {/* Metadata Count */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">Metadata Fields</td>
              <td className="py-3 text-slate-600 font-bold">{orig.metadata_count} fields</td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-emerald-700 font-bold">{clean.metadata_count} fields (Stripped)</td>
            </tr>

            {/* URLs Count */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">Discovered URLs</td>
              <td className="py-3 text-slate-600 font-bold">{orig.urls_count} URLs</td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-emerald-700 font-bold">{clean.urls_count} URLs</td>
            </tr>

            {/* JavaScript */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">Active JavaScript</td>
              <td className="py-3">
                <span className={orig.has_javascript ? 'text-rose-600 font-bold' : 'text-slate-500'}>
                  {orig.has_javascript ? 'DETECTED' : 'NO'}
                </span>
              </td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-emerald-700 font-bold">
                {clean.has_javascript ? 'DETECTED' : 'NO (Disarmed)'}
              </td>
            </tr>

            {/* VBA Macros */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">VBA Macros</td>
              <td className="py-3">
                <span className={orig.has_macros ? 'text-rose-600 font-bold' : 'text-slate-500'}>
                  {orig.has_macros ? 'DETECTED' : 'NO'}
                </span>
              </td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-emerald-700 font-bold">
                {clean.has_macros ? 'DETECTED' : 'NO (Purged)'}
              </td>
            </tr>

            {/* Attachments / OLE */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">Attachments / OLE Objects</td>
              <td className="py-3 text-slate-600 font-bold">{orig.attachments_count}</td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-emerald-700 font-bold">{clean.attachments_count}</td>
            </tr>

            {/* File Size */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">File Size</td>
              <td className="py-3 text-slate-600">{formatBytes(orig.file_size)}</td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-slate-800">{formatBytes(clean.file_size)}</td>
            </tr>

            {/* SHA-256 Hash */}
            <tr>
              <td className="py-3 font-sans font-medium text-slate-700">Cryptographic SHA-256</td>
              <td className="py-3 text-slate-500 text-[11px] truncate max-w-xs">{truncateHash(orig.sha256, 10, 10)}</td>
              <td className="py-3 text-center text-slate-300"><ArrowRight className="w-3.5 h-3.5 mx-auto" /></td>
              <td className="py-3 text-emerald-700 text-[11px] font-bold truncate max-w-xs">{truncateHash(clean.sha256, 10, 10)}</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Disarmed Items Summary Checklist */}
      {validation.removed_items.length > 0 && (
        <div className="mt-6 pt-5 border-t border-slate-100">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-3">
            Threats Disarmed & Components Purged:
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            {validation.removed_items.map((item: string, idx: number) => (
              <div key={idx} className="flex items-center gap-2 p-2 bg-emerald-50/60 rounded-xl text-emerald-950 border border-emerald-100">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                <span className="font-medium">{item}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
