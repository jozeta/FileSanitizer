import React from 'react';
import { ShieldCheck, AlertTriangle, Image as ImageIcon } from 'lucide-react';
import { UrlItem } from '../types';

interface UrlExplorerProps {
  urls?: UrlItem[];
}

export const UrlExplorer: React.FC<UrlExplorerProps> = ({ urls = [] }) => {
  if (urls.length === 0) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-8 text-center text-slate-500 shadow-sm">
        <p className="text-sm">No external URLs or hyperlinks discovered in this file.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-bold text-slate-900 tracking-tight">
          Discovered URLs & Reputation Analysis ({urls.length})
        </h3>
        <span className="text-xs text-slate-500 font-mono">
          SSRF Guard Active
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {urls.map((item, idx) => {
          return (
            <div
              key={idx}
              className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:border-slate-300 transition-all"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  {/* Top line: Protocol, Domain, Risk Badge */}
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-xs font-mono font-medium">
                      {item.protocol.toUpperCase()}
                    </span>
                    <span className="font-bold text-sm text-slate-900 truncate">
                      {item.domain || 'Unknown Host'}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase ${
                      item.risk === 'MALICIOUS' ? 'bg-rose-100 text-rose-800' :
                      item.risk === 'HIGH RISK' ? 'bg-red-100 text-red-800' :
                      item.risk === 'MEDIUM RISK' ? 'bg-amber-100 text-amber-800' :
                      'bg-emerald-100 text-emerald-800'
                    }`}>
                      {item.risk}
                    </span>
                    {item.tls_valid && (
                      <span className="text-[11px] text-emerald-600 font-mono font-medium flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3" /> TLS Valid
                      </span>
                    )}
                  </div>

                  {/* Full URL */}
                  <div className="text-xs text-slate-600 font-mono break-all mb-3 bg-slate-50 p-2 rounded-lg border border-slate-100">
                    {item.url}
                  </div>

                  {/* Reputation and SSRF indicators */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono mb-2">
                    <div className="p-2 bg-slate-50 rounded-lg">
                      <span className="text-slate-400 block text-[10px]">Heuristics</span>
                      <span className="font-semibold text-slate-700">{item.reputation.heuristic}</span>
                    </div>
                    <div className="p-2 bg-slate-50 rounded-lg">
                      <span className="text-slate-400 block text-[10px]">VirusTotal</span>
                      <span className="font-semibold text-slate-700">{item.reputation.virus_total}</span>
                    </div>
                    <div className="p-2 bg-slate-50 rounded-lg">
                      <span className="text-slate-400 block text-[10px]">URLhaus</span>
                      <span className="font-semibold text-slate-700">{item.reputation.urlhaus}</span>
                    </div>
                    <div className="p-2 bg-slate-50 rounded-lg">
                      <span className="text-slate-400 block text-[10px]">SSRF Safe</span>
                      <span className={`font-semibold ${item.is_ssrf_safe ? 'text-emerald-700' : 'text-rose-700'}`}>
                        {item.is_ssrf_safe ? 'YES (Public IP)' : 'NO (Blocked)'}
                      </span>
                    </div>
                  </div>

                  {/* Indicators / Warnings */}
                  {item.indicators.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {item.indicators.map((ind, i) => (
                        <div key={i} className="text-xs text-amber-800 flex items-center gap-1.5">
                          <AlertTriangle className="w-3 h-3 text-amber-600 shrink-0" />
                          <span>{ind}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Sandboxed Website Screenshot Preview */}
                {item.screenshot_available && item.screenshot_url && (
                  <div className="w-full md:w-56 shrink-0">
                    <div className="text-[11px] font-mono text-slate-400 mb-1 flex items-center gap-1">
                      <ImageIcon className="w-3 h-3" />
                      <span>Sandboxed Preview</span>
                    </div>
                    <div className="border border-slate-200 rounded-xl overflow-hidden shadow-sm bg-slate-100 aspect-video relative group">
                      <img
                        src={item.screenshot_url}
                        alt={`Screenshot of ${item.domain}`}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
                        loading="lazy"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
