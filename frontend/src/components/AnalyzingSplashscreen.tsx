import React, { useState, useEffect } from 'react';
import { Shield, RefreshCw, Cpu, Database, Eye, Lock, Globe, FileCode, CheckCircle2 } from 'lucide-react';
import { formatBytes } from '../utils/formatters';

interface AnalyzingSplashscreenProps {
  filename: string;
  category: string;
  fileSize: number;
  progress?: number;
  currentStep?: number;
  currentStepLabel?: string;
  isBackendReady?: boolean;
  onFinish?: () => void;
}

const ANALYSIS_STEPS = [
  { label: 'File Identification & Cryptographic Hashing', icon: Lock },
  { label: 'Antivirus Engine Inspection (ClamAV)', icon: Shield },
  { label: 'Container Dissection & Structure Verification', icon: Cpu },
  { label: 'Optical Character Recognition (OCR) on Visual Content', icon: Eye },
  { label: 'YARA Pattern Matching & Heuristic Detection', icon: Database },
  { label: 'URL Extraction & HTTPS Certificate Analysis', icon: Globe },
  { label: 'Metadata & Admin Threat Watchlist Scanning', icon: FileCode },
  { label: 'Computing Explainable Security Risk Score', icon: Shield }
];

export const AnalyzingSplashscreen: React.FC<AnalyzingSplashscreenProps> = ({
  filename,
  category,
  fileSize,
  progress = 0,
  currentStep = 1,
  currentStepLabel,
  isBackendReady = false,
  onFinish
}) => {
  const [completedCount, setCompletedCount] = useState<number>(0);
  const [allDone, setAllDone] = useState<boolean>(false);

  // Compute target completed steps based on actual backend pipeline progression
  const targetCompleted = isBackendReady
    ? ANALYSIS_STEPS.length
    : Math.max(0, Math.min(ANALYSIS_STEPS.length - 1, (currentStep > 0 ? currentStep - 1 : 0)));

  // Smoothly catch up completedCount to targetCompleted without exceeding backend reality
  useEffect(() => {
    if (completedCount < targetCompleted) {
      const stepTimer = setTimeout(() => {
        setCompletedCount((prev) => Math.min(targetCompleted, prev + 1));
      }, isBackendReady ? 80 : 150);
      return () => clearTimeout(stepTimer);
    } else if (completedCount >= ANALYSIS_STEPS.length && isBackendReady) {
      setAllDone(true);
    }
  }, [completedCount, targetCompleted, isBackendReady]);

  // Once backend is ready and all checks visually complete, cleanly hand over to parent
  useEffect(() => {
    if (isBackendReady && allDone && onFinish) {
      const timer = setTimeout(() => {
        onFinish();
      }, 600);
      return () => clearTimeout(timer);
    }
  }, [isBackendReady, allDone, onFinish]);

  // Calculate guaranteed non-NaN progress value
  const safeProgress = typeof progress === 'number' && !isNaN(progress) ? progress : 0;
  const stepProgress = Math.round((completedCount / ANALYSIS_STEPS.length) * 100);
  const rawProgress = allDone ? 100 : Math.max(safeProgress, stepProgress);
  const displayedProgress = Math.min(100, Math.max(0, isNaN(rawProgress) ? 0 : rawProgress));

  return (
    <div className="bg-white rounded-3xl border border-slate-200 shadow-sm p-8 sm:p-12 text-center max-w-3xl mx-auto my-8 relative overflow-hidden animate-modal-fade">
      {/* Background ambient radar glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* High-tech Scanning Radar Graphic */}
      <div className="relative w-32 h-32 mx-auto mb-8 flex items-center justify-center">
        {/* Outer Pulsing Wave */}
        <div className="absolute inset-0 rounded-full border-2 border-indigo-400/30 animate-ping duration-1000" />
        <div className="absolute inset-2 rounded-full border border-indigo-500/20 animate-pulse" />
        <div className="absolute inset-4 rounded-full border border-dashed border-indigo-600/30 animate-spin" style={{ animationDuration: '10s' }} />
        
        {/* Center Scanner Core */}
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-indigo-600 to-blue-600 shadow-lg shadow-indigo-500/30 flex items-center justify-center text-white relative z-10">
          <Shield className="w-8 h-8 animate-pulse" />
        </div>
      </div>

      {/* Headline & File Details */}
      <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight mb-2">
        {allDone ? '✓ Security Analysis Complete' : 'Analyzing File Security...'}
      </h2>
      <p className="text-xs text-slate-500 font-mono mb-6">
        <span className="font-semibold text-slate-700">{filename}</span> ({formatBytes(fileSize)}) • <span className="uppercase">{category}</span>
      </p>

      {/* Progress Bar */}
      <div className="w-full max-w-md mx-auto mb-8">
        <div className="flex justify-between items-center text-xs font-mono text-slate-500 mb-2">
          <span className="flex items-center gap-1.5 font-medium text-indigo-600">
            <RefreshCw className={`w-3.5 h-3.5 ${allDone ? '' : 'animate-spin'}`} />
            <span>{allDone ? 'All Pipeline Checks Verified' : (currentStepLabel || 'Multi-Engine Pipeline Active')}</span>
          </span>
          <span className="font-bold text-slate-800">{displayedProgress}%</span>
        </div>
        <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden p-0.5 border border-slate-200">
          <div
            className="bg-gradient-to-r from-indigo-600 to-blue-600 h-1.5 rounded-full transition-all duration-300 shadow-xs"
            style={{ width: `${displayedProgress}%` }}
          />
        </div>
      </div>

      {/* Live Pipeline Steps List */}
      <div className="max-w-md mx-auto text-left space-y-2.5 bg-slate-50 p-5 rounded-2xl border border-slate-200 font-mono text-xs">
        <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider mb-2 flex items-center justify-between">
          <span>Active Pipeline Checks</span>
          <span className="text-indigo-600 font-semibold">{completedCount} of {ANALYSIS_STEPS.length} Completed</span>
        </div>
        {ANALYSIS_STEPS.map((step, idx) => {
          const isDone = idx < completedCount;
          const isCurrent = idx === completedCount && !allDone;
          const Icon = step.icon;

          return (
            <div
              key={idx}
              className={`flex items-center gap-2.5 transition-all duration-200 ${
                isDone
                  ? 'text-slate-800 font-medium'
                  : isCurrent
                  ? 'text-indigo-700 font-bold bg-white px-2.5 py-1.5 rounded-xl border border-indigo-200 shadow-xs'
                  : 'text-slate-400 opacity-50'
              }`}
            >
              {isDone ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              ) : isCurrent ? (
                <RefreshCw className="w-4 h-4 text-indigo-600 animate-spin shrink-0" />
              ) : (
                <Icon className="w-4 h-4 text-slate-400 shrink-0" />
              )}
              <span className="truncate">{step.label}</span>
            </div>
          );
        })}
      </div>

      {isBackendReady && (
        <div className="mt-6">
          <button
            onClick={() => onFinish && onFinish()}
            className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-xl shadow-md transition-all cursor-pointer inline-flex items-center gap-2 animate-pulse"
          >
            <span>View Analysis Report</span>
            <CheckCircle2 className="w-4 h-4" />
          </button>
        </div>
      )}

      <p className="text-[11px] text-slate-400 mt-6 italic">
        * Original file is quarantined and sandboxed in memory. Results will be displayed automatically once full verification completes.
      </p>
    </div>
  );
};
