import React, { useState, useEffect } from 'react';
import { ShieldCheck, Clock, Info } from 'lucide-react';
import { apiClient } from '../api/client';

interface HeaderProps {
  onOpenDisclaimer: () => void;
  onReset: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onOpenDisclaimer, onReset }) => {
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    apiClient.getHealth().then(setHealth).catch(() => {});
  }, []);

  const clamavOnline = health?.clamav?.reachable ?? false;

  return (
    <header className="border-b border-slate-200 bg-white/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <button 
          onClick={onReset} 
          className="flex items-center gap-3 text-left focus:outline-none group cursor-pointer"
        >
          <div className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center shadow-sm group-hover:bg-blue-600 transition-colors">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-lg text-slate-900 tracking-tight">FileSanitizer</span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded border border-slate-200">v1.0 CDR</span>
            </div>
            <p className="text-xs text-slate-500 font-normal">Don't trust the file. Wash it first.</p>
          </div>
        </button>

        <div className="flex items-center gap-3 sm:gap-4">
          {/* ClamAV Engine Status */}
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-slate-50 border-slate-200 text-slate-700">
            <span className={`w-2 h-2 rounded-full ${clamavOnline ? 'bg-emerald-500 ring-2 ring-emerald-200' : 'bg-amber-400'}`}></span>
            <span>ClamAV: {clamavOnline ? 'Online' : 'Standby / Local'}</span>
          </div>

          {/* Retention Notice */}
          <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-slate-50 border-slate-200 text-slate-600" title="Files are automatically purged after 30 minutes">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>30m Retention</span>
          </div>

          {/* Disclaimer Button */}
          <button
            onClick={onOpenDisclaimer}
            className="flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors"
          >
            <Info className="w-4 h-4 text-slate-400" />
            <span className="hidden sm:inline">Security Disclaimer</span>
          </button>
        </div>
      </div>
    </header>
  );
};
