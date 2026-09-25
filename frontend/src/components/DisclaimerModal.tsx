import React from 'react';
import { X, ShieldAlert } from 'lucide-react';

interface DisclaimerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DisclaimerModal: React.FC<DisclaimerModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fade-in">
      <div className="bg-white rounded-3xl max-w-lg w-full p-6 sm:p-8 shadow-2xl border border-slate-200 relative">
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-2xl bg-amber-100 text-amber-800 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <h3 className="text-lg font-bold text-slate-900 tracking-tight">
            Security & CDR Disclaimer
          </h3>
        </div>

        <div className="text-sm text-slate-600 space-y-4 leading-relaxed font-normal">
          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 text-slate-800">
            <p className="font-medium mb-2">Automated Heuristic & Antivirus Scope:</p>
            <p className="text-xs text-slate-600 leading-relaxed">
              FileSanitizer performs automated security analysis and file sanitization. A <strong>"CLEAN"</strong> result indicates that no malicious content or known signatures were detected by the configured analysis engines; <strong>it does not constitute an absolute guarantee that a file is completely safe or free of novel zero-day exploits.</strong>
            </p>
          </div>

          <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 text-slate-800">
            <p className="font-medium mb-2">Content Disarm & Reconstruction Limitations:</p>
            <p className="text-xs text-slate-600 leading-relaxed">
              Sanitization drastically reduces threat surface by stripping active scripts, macros, external references, and metadata. However, sanitization does not guarantee that every conceivable exploit vector in binary parser implementations has been eliminated.
            </p>
          </div>

          <p className="text-xs text-slate-500 italic">
            Always exercise standard organizational security precautions when handling files from untrusted or unverified sources.
          </p>
        </div>

        <div className="mt-6 pt-4 border-t border-slate-100 flex justify-end">
          <button
            onClick={onClose}
            className="px-6 py-2.5 bg-slate-900 hover:bg-blue-600 text-white text-xs font-semibold rounded-xl shadow-sm transition-colors cursor-pointer"
          >
            I Understand
          </button>
        </div>
      </div>
    </div>
  );
};
