import React, { useState, useEffect } from 'react';
import { ShieldCheck, Clock, Info, BookOpen, FileCheck2, Shield, Settings, Lock, Binary } from 'lucide-react';
import { apiClient } from '../api/client';
import { APP_VERSION } from '../version';

export type ViewTab = 'sanitizer' | 'decoder' | 'how-it-works' | 'supported-formats' | 'settings';

interface HeaderProps {
  currentView: ViewTab;
  onNavigate: (view: ViewTab) => void;
  onOpenDisclaimer: () => void;
  onReset?: () => void;
  hasUpdate?: boolean;
  onOpenUpdateModal?: () => void;
}

const SECURITY_SLOGANS = [
  "Wash your bytes before you eat them.",
  "Zero Trust, 100% Detergent.",
  "There is no place like 127.0.0.1 without macros.",
  "Defanging hostile bits since 1999.",
  "Making shady attachments cry since v1.0.",
  "Laundering suspicious files ethically.",
  "Because 'Invoice.pdf.exe' is never an invoice.",
  "Soap for your suspicious payloads.",
  "Giving ransomware an existential crisis.",
  "Your digital dry cleaner for sketchy files.",
  "Disarming macros before they hatch.",
  "Trust nothing. Sanitize everything.",
  "Where suspicious macros go to die.",
  "Don't open that attachment, let us wash it.",
  "Turning weaponized PDFs into harmless pictures.",
  "No zero-days in our laundry basket.",
  "Exterminating byte bugs with forensic precision.",
  "Because curiosity killed the admin's weekend.",
  "Cleaning digital grease from untrusted sources.",
  "Treat every file like radioactive waste.",
  "Scrubbing byte dirt so you sleep at night.",
  "Stripping bad macros faster than coffee kicks in.",
  "Even clean files get a courtesy wash.",
  "Disinfecting phishing bait one click at a time.",
  "Guaranteed 99.9% malware-free or your bits back.",
  "Where LOLBins go to lose their laughs.",
  "Putting shady packets on a strict diet.",
  "Bleaching suspicious hex strings daily.",
  "De-weaponizing internet mystery files.",
  "Keep calm and sanitize the payload.",
];

export const Header: React.FC<HeaderProps> = ({ 
  currentView, 
  onNavigate, 
  onOpenDisclaimer,
  hasUpdate,
  onOpenUpdateModal,
}) => {
  const [health, setHealth] = useState<any>(null);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(() => !!localStorage.getItem('fs_admin_token'));
  const [slogan] = useState<string>(() => {
    return SECURITY_SLOGANS[Math.floor(Math.random() * SECURITY_SLOGANS.length)];
  });

  useEffect(() => {
    apiClient.getHealth().then(setHealth).catch(() => {});

    const checkAuth = () => {
      setIsLoggedIn(!!localStorage.getItem('fs_admin_token'));
    };
    window.addEventListener('storage', checkAuth);
    window.addEventListener('auth_changed', checkAuth);
    return () => {
      window.removeEventListener('storage', checkAuth);
      window.removeEventListener('auth_changed', checkAuth);
    };
  }, []);

  const clamavOnline = health?.clamav?.reachable ?? false;

  return (
    <header className="border-b border-slate-200 bg-white/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-[96rem] mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Logo and Brand */}
        <div className="flex items-center gap-3 text-left shrink-0">
          <button 
            type="button"
            onClick={() => onNavigate('sanitizer')} 
            className="flex items-center gap-3 text-left focus:outline-none group cursor-pointer"
          >
            <div className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center shadow-sm group-hover:bg-blue-600 transition-colors">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-lg text-slate-900 tracking-tight">FileSanitizer</span>
                <span className="text-[11px] font-mono px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded border border-slate-200">v{APP_VERSION} CDR</span>
              </div>
              <p className="text-xs text-slate-500 font-normal hidden sm:block">{slogan}</p>
            </div>
          </button>

          {hasUpdate && onOpenUpdateModal && (
            <button
              type="button"
              onClick={onOpenUpdateModal}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-100 hover:bg-amber-200 text-amber-900 border border-amber-300 transition-colors shadow-2xs cursor-pointer ml-1"
              title="New FileSanitizer version available! Click to view details."
            >
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-ping" />
              <span>Update Available</span>
            </button>
          )}
        </div>

        {/* Center Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-slate-100/80 p-1 rounded-2xl border border-slate-200/80">
          <button
            onClick={() => onNavigate('sanitizer')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              currentView === 'sanitizer'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Sanitizer</span>
          </button>

          <button
            onClick={() => onNavigate('decoder')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              currentView === 'decoder'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Binary className="w-3.5 h-3.5" />
            <span>Decoder</span>
          </button>

          <button
            onClick={() => onNavigate('how-it-works')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              currentView === 'how-it-works'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>How It Works</span>
          </button>

          <button
            onClick={() => onNavigate('supported-formats')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              currentView === 'supported-formats'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <FileCheck2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Supported Formats</span>
            <span className="sm:hidden">Formats</span>
          </button>

          <button
            onClick={() => onNavigate('settings')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              currentView === 'settings'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            {isLoggedIn ? (
              <>
                <Settings className="w-3.5 h-3.5" />
                <span>Settings</span>
              </>
            ) : (
              <>
                <Lock className="w-3.5 h-3.5" />
                <span>Login</span>
              </>
            )}
          </button>
        </nav>

        {/* Right Status Badges & Disclaimer */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {/* ClamAV Engine Status */}
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-slate-50 border-slate-200 text-slate-700">
            <span className={`w-2 h-2 rounded-full ${clamavOnline ? 'bg-emerald-500 ring-2 ring-emerald-200' : 'bg-amber-400'}`}></span>
            <span>ClamAV: {clamavOnline ? 'Online' : 'Standby'}</span>
          </div>

          {/* Retention Notice */}
          <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border bg-slate-50 border-slate-200 text-slate-600" title="Files are automatically purged after 30 minutes">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>30m Retention</span>
          </div>

          {/* Disclaimer Button */}
          <button
            onClick={onOpenDisclaimer}
            className="flex items-center gap-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 px-2.5 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer"
            title="Security Disclaimer"
          >
            <Info className="w-4 h-4 text-slate-400" />
            <span className="hidden xl:inline">Security Disclaimer</span>
          </button>
        </div>
      </div>
    </header>
  );
};
