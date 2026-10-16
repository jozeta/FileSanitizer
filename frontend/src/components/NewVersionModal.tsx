import React from 'react';
import { Sparkles, ExternalLink, X, ArrowRight, BellOff, Github, Calendar, Tag } from 'lucide-react';
import { UpdateCheckResult } from '../api/client';

interface NewVersionModalProps {
  isOpen: boolean;
  onClose: () => void;
  updateInfo: UpdateCheckResult | null;
  onDisableFutureChecks: () => void;
}

export const NewVersionModal: React.FC<NewVersionModalProps> = ({
  isOpen,
  onClose,
  updateInfo,
  onDisableFutureChecks,
}) => {
  if (!isOpen || !updateInfo) return null;

  const currentVersion = updateInfo.current_version || '2.4.0';
  const latestVersion = updateInfo.latest_version || 'Unknown';
  const releaseName = updateInfo.release_name || `FileSanitizer v${latestVersion}`;
  const releaseNotes = updateInfo.release_notes || '';
  const publishedAt = updateInfo.published_at;
  const githubUrl = updateInfo.html_url || 'https://github.com/jozeta/FileSanitizer';

  // Format date if valid
  let formattedDate: string | null = null;
  if (publishedAt) {
    try {
      const d = new Date(publishedAt);
      if (!isNaN(d.getTime())) {
        formattedDate = d.toLocaleDateString(undefined, {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
        });
      } else {
        formattedDate = publishedAt;
      }
    } catch {
      formattedDate = publishedAt;
    }
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 animate-in fade-in duration-200">
      <div 
        className="relative bg-white rounded-3xl shadow-2xl max-w-lg w-full border border-slate-200 overflow-hidden transform transition-all"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-headline"
      >
        {/* Top Gradient Banner */}
        <div className="h-2.5 bg-gradient-to-r from-blue-600 via-indigo-600 to-emerald-500 w-full" />

        {/* Modal Close Button */}
        <button
          onClick={onClose}
          type="button"
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 hover:bg-slate-100 p-2 rounded-xl transition-all cursor-pointer"
          title="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="p-6 sm:p-7 space-y-6">
          {/* Header Title with Icon */}
          <div className="flex items-start gap-4 pr-6">
            <div className="w-12 h-12 rounded-2xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0 shadow-xs">
              <Sparkles className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-amber-100 text-amber-900 border border-amber-200 mb-1.5 font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-ping" />
                Update Available
              </div>
              <h2 id="modal-headline" className="text-lg font-bold text-slate-900 leading-snug">
                New Version of FileSanitizer is Available
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                A newer release has been published on GitHub with new security features and analysis updates.
              </p>
            </div>
          </div>

          {/* Version Comparison Card */}
          <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 flex items-center justify-between gap-3 shadow-2xs">
            {/* Current version */}
            <div className="flex flex-col">
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">
                Installed
              </span>
              <span className="text-sm font-bold text-slate-700 font-mono mt-0.5">
                v{currentVersion}
              </span>
            </div>

            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-white border border-slate-200 shadow-2xs text-slate-400">
              <ArrowRight className="w-4 h-4 text-indigo-500" />
            </div>

            {/* New version */}
            <div className="flex flex-col text-right">
              <span className="text-[11px] font-semibold text-emerald-600 uppercase tracking-wider font-mono flex items-center justify-end gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block" />
                Latest on GitHub
              </span>
              <span className="text-base font-extrabold text-emerald-600 font-mono mt-0.5">
                v{latestVersion}
              </span>
            </div>
          </div>

          {/* Release Highlights / Metadata */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-indigo-500" />
                {releaseName}
              </span>
              {formattedDate && (
                <span className="flex items-center gap-1 font-mono text-[11px]">
                  <Calendar className="w-3.5 h-3.5 text-slate-400" />
                  {formattedDate}
                </span>
              )}
            </div>

            {releaseNotes && (
              <div className="bg-white border border-slate-200 rounded-2xl p-3.5 max-h-40 overflow-y-auto text-xs text-slate-600 space-y-1 font-mono leading-relaxed shadow-inner">
                {releaseNotes.split('\n').filter(Boolean).map((line, idx) => (
                  <p key={idx} className="break-words">
                    {line}
                  </p>
                ))}
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="space-y-2 pt-2">
            <a
              href={githubUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-2xl text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 shadow-sm transition-all cursor-pointer group"
            >
              <Github className="w-4 h-4" />
              <span>View Release &amp; Changelog on GitHub</span>
              <ExternalLink className="w-3.5 h-3.5 opacity-70 group-hover:opacity-100 transition-opacity" />
            </a>

            <div className="flex items-center gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-2.5 rounded-2xl text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 transition-colors cursor-pointer"
              >
                Remind Me Later
              </button>

              <button
                type="button"
                onClick={onDisableFutureChecks}
                className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2.5 rounded-2xl text-xs font-medium text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors cursor-pointer"
                title="Turn off automatic check in settings"
              >
                <BellOff className="w-3.5 h-3.5 text-slate-400" />
                <span>Don't Check Again</span>
              </button>
            </div>
          </div>

          {/* Footer Subtext */}
          <p className="text-[11px] text-center text-slate-400">
            You can always re-enable or change update check preferences in{' '}
            <strong className="text-slate-500 font-medium">Settings &rarr; UI &amp; Display</strong>.
          </p>
        </div>
      </div>
    </div>
  );
};
