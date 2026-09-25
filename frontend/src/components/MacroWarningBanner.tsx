import React from 'react';
import { AlertOctagon, Terminal } from 'lucide-react';

interface MacroWarningBannerProps {
  macroDetails?: any[];
}

export const MacroWarningBanner: React.FC<MacroWarningBannerProps> = ({ macroDetails = [] }) => {
  return (
    <div className="bg-rose-500/10 border-2 border-rose-500/30 rounded-2xl p-5 text-rose-950 mb-6 shadow-sm">
      <div className="flex items-start gap-4">
        <div className="p-3 bg-rose-600 text-white rounded-xl shadow-md shrink-0">
          <AlertOctagon className="w-8 h-8" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-1">
            <h3 className="text-lg font-bold tracking-tight text-rose-700 uppercase">
              MACROS DETECTED
            </h3>
            <span className="px-2 py-0.5 bg-rose-100 text-rose-800 text-xs font-semibold rounded border border-rose-200">
              CRITICAL EXECUTION RISK
            </span>
          </div>
          <p className="text-sm text-rose-900 leading-relaxed font-medium">
            This document contains embedded <strong>Visual Basic for Applications (VBA) macros</strong> or auto-executing scripts. 
            Do <strong>NOT</strong> open this file on your workstation or enable content in Microsoft Office under any circumstances.
          </p>

          {macroDetails.length > 0 && (
            <div className="mt-4 pt-3 border-t border-rose-200/80">
              <div className="flex items-center gap-2 text-xs font-semibold text-rose-800 mb-2">
                <Terminal className="w-4 h-4 text-rose-600" />
                <span>Detected Macro Triggers & Suspicious Keywords ({macroDetails.length})</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                {macroDetails.slice(0, 6).map((m, idx) => (
                  <div key={idx} className="bg-white/80 border border-rose-200 px-2.5 py-1.5 rounded-lg flex items-center justify-between text-rose-950">
                    <span className="font-semibold">{m.keyword || m.type}</span>
                    <span className="text-[11px] text-rose-700">{m.description || m.type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
