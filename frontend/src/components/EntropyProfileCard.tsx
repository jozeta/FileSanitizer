import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, CheckCircle, RefreshCw, BarChart3, Binary, Layers } from 'lucide-react';
import { EntropyProfile, EntropyChunk } from '../types';

interface EntropyProfileCardProps {
  jobId: string;
  entropy?: EntropyProfile;
}

export const EntropyProfileCard: React.FC<EntropyProfileCardProps> = ({ jobId, entropy: initialEntropy }) => {
  const [profileData, setProfileData] = useState<EntropyProfile | undefined>(initialEntropy);
  const [loading, setLoading] = useState(false);
  const [hoveredChunk, setHoveredChunk] = useState<EntropyChunk | null>(null);

  const reloadEntropy = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/jobs/${jobId}/entropy`);
      if (res.ok) {
        const data = await res.json();
        setProfileData(data);
      }
    } catch (err) {
      console.error('Failed to load entropy profile:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialEntropy && initialEntropy.profile && initialEntropy.profile.length > 0) {
      setProfileData(initialEntropy);
    } else if (jobId) {
      reloadEntropy();
    }
  }, [jobId, initialEntropy]);

  const currentEntropy = profileData || initialEntropy;

  if (loading && (!currentEntropy || !currentEntropy.profile || currentEntropy.profile.length === 0)) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-12 shadow-sm text-center">
        <RefreshCw className="w-8 h-8 text-indigo-500 animate-spin mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-800 mb-1">Computing Shannon Entropy Profile...</h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          Calculating byte randomness distribution, Chi-Square metrics, and sliding-window entropy blocks.
        </p>
      </div>
    );
  }

  if (!currentEntropy || !currentEntropy.profile || currentEntropy.profile.length === 0) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Activity className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-800 mb-1">Shannon Entropy Profile</h3>
        <p className="text-sm text-slate-500 max-w-md mx-auto mb-4">
          Detailed byte distribution and sliding-window entropy have not been calculated for this file yet.
        </p>
        <button
          onClick={reloadEntropy}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-sm font-semibold rounded-xl border border-indigo-200 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Compute Entropy Profile</span>
        </button>
      </div>
    );
  }

  const overall = currentEntropy.overall_entropy;
  const isHighEntropy = currentEntropy.verdict === 'SUSPICIOUS_HIGH_ENTROPY' || overall >= 7.1;
  const highChunks = currentEntropy.profile.filter((c) => c.entropy >= 7.1);

  return (
    <div className="space-y-6">
      {/* Header and Summary Banner */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="p-1.5 bg-indigo-50 text-indigo-600 rounded-lg">
                <BarChart3 className="w-5 h-5" />
              </span>
              <h3 className="text-lg font-bold text-slate-900">
                Shannon Entropy & Byte Distribution Profile
              </h3>
            </div>
            <p className="text-xs text-slate-500 font-mono">
              Sliding-window byte randomness (0.0 to 8.0) to detect packed shellcode, encrypted droppers, and trailing overlays.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span
              className={`px-3 py-1.5 rounded-xl text-xs font-bold font-mono uppercase tracking-wider inline-flex items-center gap-1.5 border ${
                isHighEntropy
                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}
            >
              {isHighEntropy ? (
                <>
                  <ShieldAlert className="w-4 h-4 text-rose-600" />
                  <span>Suspicious / High Entropy</span>
                </>
              ) : (
                <>
                  <CheckCircle className="w-4 h-4 text-emerald-600" />
                  <span>Normal Entropy Distribution</span>
                </>
              )}
            </span>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-6">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
              Overall Entropy
            </span>
            <div className="flex items-baseline gap-1">
              <span
                className={`text-2xl font-mono font-extrabold ${
                  overall >= 7.1 ? 'text-rose-600' : overall >= 5.8 ? 'text-amber-600' : 'text-slate-800'
                }`}
              >
                {overall.toFixed(2)}
              </span>
              <span className="text-xs font-mono text-slate-400">/ 8.00</span>
            </div>
            <span className="text-[10px] text-slate-500 block mt-1">
              {overall >= 7.1
                ? 'Packed / Encrypted'
                : overall >= 5.8
                ? 'Compiled Binary / Code'
                : 'Structured Text / Markup'}
            </span>
          </div>

          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
              Chi-Square Test
            </span>
            <span className="text-2xl font-mono font-extrabold text-slate-800">
              {currentEntropy.chi_square?.chi_square ?? 'N/A'}
            </span>
            <span className="text-[10px] text-slate-500 block mt-1 truncate">
              {currentEntropy.chi_square?.is_random_like
                ? 'High Uniformity (Random-like)'
                : 'Natural Variance'}
            </span>
          </div>

          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
              Monte Carlo Pi
            </span>
            <span className="text-2xl font-mono font-extrabold text-slate-800">
              {currentEntropy.monte_carlo?.pi_estimate?.toFixed(4) ?? '3.1415'}
            </span>
            <span className="text-[10px] text-slate-500 block mt-1">
              {currentEntropy.monte_carlo?.error_percent !== undefined
                ? `${currentEntropy.monte_carlo.error_percent.toFixed(2)}% deviation`
                : 'Deviation from π'}
            </span>
          </div>

          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
              Byte Densities
            </span>
            <div className="text-xs font-mono text-slate-700 space-y-0.5">
              <div>
                Nulls: <span className="font-bold">{currentEntropy.null_byte_percentage ?? 0}%</span>
              </div>
              <div>
                Printable: <span className="font-bold">{currentEntropy.printable_byte_percentage ?? 0}%</span>
              </div>
            </div>
          </div>
        </div>

        {/* Sliding Window Visual Heatmap */}
        <div className="mt-8 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-indigo-500" />
              <span>Sliding Window Entropy Map ({currentEntropy.profile.length} Chunks)</span>
            </h4>
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-rose-500" /> High (≥7.1)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-amber-400" /> Code (5.8–7.0)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-blue-400" /> Plain (3.2–5.7)
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-slate-300" /> Sparse (&lt;3.2)
              </span>
            </div>
          </div>

          {/* Interactive Chart Bars */}
          <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4">
            <div className="h-28 flex items-end gap-1 sm:gap-1.5 pt-4 pb-1 relative">
              {currentEntropy.profile.map((chunk) => {
                const heightPercent = Math.max(8, Math.min(100, (chunk.entropy / 8.0) * 100));
                const barColor =
                  chunk.entropy >= 7.1
                    ? 'bg-rose-500 hover:bg-rose-600'
                    : chunk.entropy >= 5.8
                    ? 'bg-amber-400 hover:bg-amber-500'
                    : chunk.entropy >= 3.2
                    ? 'bg-blue-400 hover:bg-blue-500'
                    : 'bg-slate-300 hover:bg-slate-400';

                return (
                  <div
                    key={chunk.index}
                    className="flex-1 h-full flex items-end group relative cursor-pointer"
                    onMouseEnter={() => setHoveredChunk(chunk)}
                    onMouseLeave={() => setHoveredChunk(null)}
                  >
                    <div
                      style={{ height: `${heightPercent}%` }}
                      className={`w-full rounded-t-sm transition-all ${barColor}`}
                    />
                  </div>
                );
              })}
            </div>

            {/* X-Axis File Offset Labels */}
            <div className="flex justify-between text-[10px] font-mono text-slate-400 pt-2 border-t border-slate-200">
              <span>0x000000 (File Start)</span>
              <span>Offset 50%</span>
              <span>
                {currentEntropy.profile[currentEntropy.profile.length - 1]?.offset_hex.split('-')[1]?.trim() || 'EOF'}
              </span>
            </div>
          </div>

          {/* Hovered Chunk Details Inspector */}
          {hoveredChunk && (
            <div className="p-3 bg-indigo-50/70 border border-indigo-100 rounded-xl flex flex-wrap items-center justify-between text-xs font-mono gap-2 animate-fadeIn">
              <div className="flex items-center gap-2">
                <span className="font-bold text-indigo-900">Chunk #{hoveredChunk.index + 1}:</span>
                <span className="text-indigo-700">{hoveredChunk.offset_hex}</span>
                <span className="text-slate-500">({hoveredChunk.chunk_size} bytes)</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-bold text-slate-800">
                  Entropy: <span className="text-indigo-900">{hoveredChunk.entropy.toFixed(3)} / 8.00</span>
                </span>
                <span className="text-slate-600">{hoveredChunk.label}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* High Entropy Regions Table */}
      {highChunks.length > 0 && (
        <div className="bg-white rounded-3xl border border-rose-200 p-6 sm:p-8 shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <span className="p-1.5 bg-rose-50 text-rose-600 rounded-lg">
              <Binary className="w-5 h-5" />
            </span>
            <div>
              <h4 className="text-sm font-bold text-slate-900">
                High-Entropy Payloads & Packed Sections ({highChunks.length} Block{highChunks.length > 1 ? 's' : ''})
              </h4>
              <p className="text-xs text-slate-500">
                Offsets where randomness exceeds 7.1 / 8.0, typical of packed executables, encrypted droppers, or stego overlays.
              </p>
            </div>
          </div>

          <div className="overflow-x-auto rounded-2xl border border-slate-200">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-50 text-slate-500 uppercase tracking-wider text-[10px] border-b border-slate-200">
                <tr>
                  <th className="py-2.5 px-4">Offset Range</th>
                  <th className="py-2.5 px-4">Block Size</th>
                  <th className="py-2.5 px-4">Entropy</th>
                  <th className="py-2.5 px-4">Classification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {highChunks.map((chunk) => (
                  <tr key={chunk.index} className="hover:bg-rose-50/40 transition-colors">
                    <td className="py-2.5 px-4 font-bold text-slate-800">{chunk.offset_hex}</td>
                    <td className="py-2.5 px-4 text-slate-600">{chunk.chunk_size} bytes</td>
                    <td className="py-2.5 px-4 font-extrabold text-rose-600">{chunk.entropy.toFixed(3)} / 8.00</td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 bg-rose-100 text-rose-800 rounded text-[10px] font-bold">
                        Packed / Encrypted Stream
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
