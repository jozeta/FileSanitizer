import React from 'react';
import { UploadCloud, File, ShieldCheck, Loader2 } from 'lucide-react';
import { formatBytes } from '../utils/formatters';

interface UploadProgressModalProps {
  files: File[];
  progress: { loaded: number; total: number; percentage: number } | null;
}

export const UploadProgressModal: React.FC<UploadProgressModalProps> = ({ files, progress }) => {
  const percentage = progress ? progress.percentage : 0;
  const isComplete = percentage >= 100;
  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/35 backdrop-blur-xs animate-overlay-fade">
      <div className="bg-white border border-slate-200 rounded-3xl shadow-2xl max-w-lg w-full p-6 sm:p-8 space-y-6 relative overflow-hidden">
        {/* Animated Accent Top Border */}
        <div className="absolute top-0 left-0 right-0 h-1.5 bg-linear-to-r from-blue-500 via-indigo-600 to-sky-500" />

        {/* Central Graphic & Header */}
        <div className="text-center space-y-3 pt-2">
          {/* Pulsing Upload Graphic */}
          <div className="relative mx-auto w-20 h-20 flex items-center justify-center">
            {/* Outer expanding ping ring */}
            <div className="absolute inset-0 rounded-full bg-blue-400/20 animate-ping" />
            
            {/* Middle soft glowing circle */}
            <div className="absolute -inset-1.5 rounded-full bg-linear-to-tr from-blue-100 to-indigo-100 animate-pulse" />
            
            {/* Core icon container */}
            <div className="relative w-16 h-16 rounded-2xl bg-linear-to-b from-blue-50 to-indigo-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-sm">
              {isComplete ? (
                <Loader2 className="w-8 h-8 text-indigo-600 animate-spin" />
              ) : (
                <UploadCloud className="w-8 h-8 text-blue-600 animate-bounce" />
              )}
            </div>
          </div>

          <div>
            <h3 className="text-lg font-bold text-slate-900 tracking-tight">
              {isComplete ? 'Processing Ingested File...' : 'Uploading for Forensic Analysis'}
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              {isComplete
                ? 'Streaming complete! Handing over to dissection engine...'
                : 'Securely transferring binary payload to isolated inspection workspace'}
            </p>
          </div>
        </div>

        {/* Files Roster */}
        <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-3.5 space-y-2 max-h-36 overflow-y-auto">
          {files.map((file, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between text-xs py-1 px-2 rounded-xl bg-white border border-slate-100"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <File className="w-4 h-4 text-blue-600 shrink-0" />
                <span className="font-semibold text-slate-800 truncate max-w-[240px]" title={file.name}>
                  {file.name}
                </span>
              </div>
              <span className="font-mono text-[11px] text-slate-500 shrink-0 ml-2">
                {formatBytes(file.size)}
              </span>
            </div>
          ))}
        </div>

        {/* Progress Bar & Counters */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="font-semibold text-slate-700 flex items-center gap-1.5">
              {!isComplete ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping inline-block" />
                  <span>Uploading stream...</span>
                </>
              ) : (
                <>
                  <Loader2 className="w-3.5 h-3.5 text-indigo-600 animate-spin" />
                  <span>Dissecting container structure...</span>
                </>
              )}
            </span>
            <span className="font-bold text-blue-600 text-sm">{percentage}%</span>
          </div>

          {/* Progress Bar Track */}
          <div className="w-full bg-slate-100 h-3 rounded-full border border-slate-200/80 overflow-hidden p-0.5 shadow-inner">
            <div
              className="h-full rounded-full bg-linear-to-r from-blue-600 via-indigo-600 to-blue-500 transition-all duration-150 ease-out shadow-xs"
              style={{ width: `${Math.max(percentage, 4)}%` }}
            />
          </div>

          {/* Byte Transfer Readout */}
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
            <span>
              {formatBytes(progress?.loaded || 0)} / {formatBytes(progress?.total || totalBytes)} transferred
            </span>
            <span>
              {isComplete ? '100% Uploaded' : `${percentage}% uploaded`}
            </span>
          </div>
        </div>

        {/* Security & Isolation Assurance Footer */}
        <div className="pt-2 border-t border-slate-100 flex items-center justify-center gap-1.5 text-[11px] text-slate-500 font-medium">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>Zero-Trust Sandbox • Memory-buffered • Ephemeral isolation</span>
        </div>
      </div>
    </div>
  );
};
