import React, { useState } from 'react';
import {
  GitFork,
  Copy,
  Check,
  ExternalLink,
  Info,
  Clock,
  Fingerprint
} from 'lucide-react';
import { SimilarSampleMatch } from '../types';

interface SimilarityClusterCardProps {
  hashes?: Record<string, string>;
  similarSamples?: SimilarSampleMatch[];
  onSelectJob?: (jobId: string) => void;
}

export const SimilarityClusterCard: React.FC<SimilarityClusterCardProps> = ({
  hashes = {},
  similarSamples = [],
  onSelectJob
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const ssdeep = hashes.ssdeep || '';
  const tlsh = hashes.tlsh || '';

  return (
    <div className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
      {/* Header */}
      <div className="p-4 bg-slate-50/70 border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-50 border border-purple-200 flex items-center justify-center text-purple-600">
            <GitFork className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900">Fuzzy Hashing & Similarity Clustering</h3>
            <p className="text-[11px] text-slate-500">
              Locality-sensitive hashing (SSDEEP & TLSH) for polymorphic variant matching and code lineage clustering
            </p>
          </div>
        </div>

        {similarSamples.length > 0 && (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-purple-100 text-purple-800 border border-purple-200">
            {similarSamples.length} Related Variant{similarSamples.length > 1 ? 's' : ''} Found
          </span>
        )}
      </div>

      <div className="p-5 space-y-5">
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
              {ssdeep || 'Not calculated for this input format'}
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
              {tlsh || 'Not calculated for this input format'}
            </div>
          </div>
        </div>

        {/* Similar Variants Cluster Table */}
        {similarSamples.length > 0 ? (
          <div>
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2.5 flex items-center gap-2">
              <GitFork className="w-3.5 h-3.5 text-purple-600" />
              <span>Matching Historical Submissions & Mutated Variants</span>
            </h4>

            <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100">
              {similarSamples.map((sample, idx) => {
                const isMalicious = ['MALICIOUS', 'CRITICAL', 'HIGH'].includes((sample.risk_level || '').toUpperCase());
                return (
                  <div
                    key={idx}
                    className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-50/80 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-900">{sample.filename}</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          isMalicious ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-700'
                        }`}>
                          {sample.risk_level || 'UNKNOWN'}
                        </span>
                        {sample.verdict && (
                          <span className="text-[11px] text-slate-500 font-medium">({sample.verdict})</span>
                        )}
                      </div>

                      <div className="flex items-center gap-3 text-[11px] text-slate-500 font-mono">
                        <span className="truncate max-w-[220px]">SHA-256: {sample.sha256}</span>
                        {sample.uploaded_at && (
                          <span className="flex items-center gap-1 text-slate-400">
                            <Clock className="w-3 h-3" />
                            {new Date(sample.uploaded_at).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Similarity Score & Action */}
                    <div className="flex items-center gap-3 shrink-0">
                      <div className="text-right">
                        <div className="flex items-center gap-2">
                          <div className="w-24 bg-slate-100 h-2 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                sample.similarity >= 75 ? 'bg-rose-500' :
                                sample.similarity >= 50 ? 'bg-amber-500' : 'bg-slate-400'
                              }`}
                              style={{ width: `${Math.min(100, sample.similarity)}%` }}
                            />
                          </div>
                          <span className="text-xs font-black font-mono text-slate-800">
                            {sample.similarity}%
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-400">Fuzzy Match Score</span>
                      </div>

                      {onSelectJob && sample.job_id && (
                        <button
                          onClick={() => onSelectJob(sample.job_id)}
                          className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <span>Inspect</span>
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="p-4 bg-slate-50 border border-slate-200/80 rounded-xl text-xs text-slate-600 flex items-center gap-2.5">
            <Info className="w-4 h-4 text-slate-400 shrink-0" />
            <span>
              No high-confidence fuzzy variant clusters found in previous uploads. This file has distinct block sequences compared to past samples.
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
