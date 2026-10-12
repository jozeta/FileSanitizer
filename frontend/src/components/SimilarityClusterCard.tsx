import React, { useState } from 'react';
import {
  Copy,
  Check,
  Fingerprint
} from 'lucide-react';

interface SimilarityClusterCardProps {
  hashes?: Record<string, string>;
  similarSamples?: any[];
  onSelectJob?: (jobId: string) => void;
}

export const SimilarityClusterCard: React.FC<SimilarityClusterCardProps> = ({
  hashes = {},
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const ssdeep = hashes.ssdeep || '';
  const tlsh = hashes.tlsh || '';

  // If neither ssdeep nor tlsh exists, do not render an empty card
  if (!ssdeep && !tlsh) {
    return null;
  }

  return (
    <div className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
      {/* Header */}
      <div className="p-4 bg-slate-50/70 border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-50 border border-purple-200 flex items-center justify-center text-purple-600">
            <Fingerprint className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">Locality-Sensitive &amp; Fuzzy Hashes</h3>
            <p className="text-[11px] text-slate-500">
              Context-triggered piecewise hashing (SSDEEP) and Trend Micro Locality Sensitive Hash (TLSH)
            </p>
          </div>
        </div>
      </div>

      <div className="p-5">
        {/* Locality-Sensitive Hashes */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* SSDEEP */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <Fingerprint className="w-3.5 h-3.5 text-purple-600" />
                SSDEEP (CTPH)
              </span>
              {ssdeep && (
                <button
                  onClick={() => handleCopy('ssdeep', ssdeep)}
                  className="text-slate-400 hover:text-purple-600 p-1 rounded-md transition-colors cursor-pointer"
                  title="Copy SSDEEP"
                >
                  {copiedKey === 'ssdeep' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              )}
            </div>
            <div className="font-mono text-xs text-slate-800 break-all select-all bg-white p-2 rounded-lg border border-slate-200/80">
              {ssdeep || 'Not calculated'}
            </div>
          </div>

          {/* TLSH */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <Fingerprint className="w-3.5 h-3.5 text-indigo-600" />
                TLSH Locality Hash
              </span>
              {tlsh && (
                <button
                  onClick={() => handleCopy('tlsh', tlsh)}
                  className="text-slate-400 hover:text-indigo-600 p-1 rounded-md transition-colors cursor-pointer"
                  title="Copy TLSH"
                >
                  {copiedKey === 'tlsh' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              )}
            </div>
            <div className="font-mono text-xs text-slate-800 break-all select-all bg-white p-2 rounded-lg border border-slate-200/80">
              {tlsh || 'Not calculated'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
