import React, { useState } from 'react';
import {
  X,
  FileCode,
  Download,
  Play,
  Copy,
  Check,
  Image,
  Binary,
  ShieldAlert,
  ZoomIn,
  ZoomOut,
  Maximize2
} from 'lucide-react';
import { PcapCarvedFile } from '../types';

interface CarvedFilePreviewModalProps {
  file: PcapCarvedFile | null;
  onClose: () => void;
  onDownload: (file: PcapCarvedFile) => void;
  onAnalyze: (file: PcapCarvedFile) => void;
  isAnalyzing?: boolean;
}

export const CarvedFilePreviewModal: React.FC<CarvedFilePreviewModalProps> = ({
  file,
  onClose,
  onDownload,
  onAnalyze,
  isAnalyzing = false
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [imageZoom, setImageZoom] = useState<number>(1);
  const [wordWrap, setWordWrap] = useState<boolean>(true);

  if (!file) return null;

  const handleCopyText = () => {
    if (file.preview_text) {
      navigator.clipboard.writeText(file.preview_text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const isImage = file.preview_type === 'image' || Boolean(file.preview_base64);
  const isText = file.preview_type === 'text';

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6 animate-in fade-in duration-200">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 px-6 border-b border-slate-200 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center gap-3 truncate">
            <div className={`p-2 rounded-xl ${
              isImage ? 'bg-purple-100 text-purple-700' : isText ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-700'
            }`}>
              {isImage ? <Image className="w-5 h-5" /> : isText ? <FileCode className="w-5 h-5" /> : <Binary className="w-5 h-5" />}
            </div>
            <div className="truncate">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-900 truncate font-mono">
                  {file.filename || file.name}
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                  {file.mime_type}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                  {file.size_formatted}
                </span>
              </div>
              <p className="text-xs text-slate-500 font-mono mt-0.5">
                Extracted via {file.source_protocol} • Stream: {file.source_stream}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onDownload(file)}
              className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </button>

            <button
              onClick={() => onAnalyze(file)}
              disabled={isAnalyzing}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isAnalyzing ? 'Queuing...' : 'Analyze in Sandbox'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 hover:bg-slate-200 rounded-lg text-slate-400 hover:text-slate-700 transition-colors ml-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Hashes and Reputation Sub-bar */}
        <div className="p-3 px-6 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-4 text-slate-600">
            <div>
              <span className="text-slate-400 mr-1.5">SHA-256:</span>
              <span className="font-semibold select-all">{file.sha256}</span>
            </div>
            <div>
              <span className="text-slate-400 mr-1.5">MD5:</span>
              <span className="font-semibold select-all">{file.md5}</span>
            </div>
          </div>

          {file.is_dangerous && (
            <div className="flex items-center gap-1.5 text-rose-700 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded text-[11px] font-semibold">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
              <span>{file.threat_reason || 'Flagged Suspicious Artifact'}</span>
            </div>
          )}
        </div>

        {/* Modal Body / Viewer */}
        <div className="flex-1 overflow-y-auto p-5 bg-slate-100/50">
          {/* IMAGE PREVIEW */}
          {isImage && file.preview_base64 ? (
            <div className="flex flex-col items-center justify-center p-6 bg-white border border-slate-200 rounded-xl min-h-[350px] space-y-4">
              {/* Image Toolbar */}
              <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
                <button
                  onClick={() => setImageZoom((z) => Math.min(3, z + 0.25))}
                  className="p-1 hover:bg-white rounded text-slate-600"
                  title="Zoom In"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <span className="px-2 font-mono text-[11px] text-slate-600">
                  {Math.round(imageZoom * 100)}%
                </span>
                <button
                  onClick={() => setImageZoom((z) => Math.max(0.25, z - 0.25))}
                  className="p-1 hover:bg-white rounded text-slate-600"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setImageZoom(1)}
                  className="p-1 hover:bg-white rounded text-slate-600"
                  title="Reset Zoom"
                >
                  <Maximize2 className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Rendered Image */}
              <div className="max-w-full max-h-[480px] overflow-auto border border-slate-200 rounded-lg p-2 bg-slate-50/50 shadow-inner flex items-center justify-center">
                <img
                  src={file.preview_base64}
                  alt={file.filename}
                  style={{ transform: `scale(${imageZoom})`, transformOrigin: 'center center' }}
                  className="max-h-[420px] max-w-full object-contain rounded transition-transform duration-150"
                />
              </div>

              <div className="text-[11px] text-slate-500 font-mono text-center">
                Visual Artifact Preview • {file.size_formatted} • Reconstructed from Network Packets
              </div>
            </div>
          ) : isText ? (
            /* TEXT / CODE PREVIEW */
            <div className="flex flex-col bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
              <div className="p-2.5 px-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-700">Text Content Preview</span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    ({file.preview_text?.length || 0} characters)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setWordWrap(!wordWrap)}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium border transition-colors ${
                      wordWrap ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'bg-white border-slate-200 text-slate-600'
                    }`}
                  >
                    Wrap Lines
                  </button>
                  <button
                    onClick={handleCopyText}
                    className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 font-medium flex items-center gap-1 transition-colors"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy Text'}</span>
                  </button>
                </div>
              </div>

              <div className="p-4 max-h-[500px] overflow-y-auto font-mono text-xs leading-5 bg-white text-slate-800">
                <pre className={`whitespace-${wordWrap ? 'pre-wrap' : 'pre'} break-all font-mono select-text`}>
                  {file.preview_text || 'No text extracted from payload.'}
                </pre>
              </div>
            </div>
          ) : (
            /* HEX DUMP PREVIEW FOR BINARIES / ARCHIVES */
            <div className="flex flex-col bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
              <div className="p-2.5 px-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-700">Binary Hexadecimal Dump (First 2KB)</span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Offset / Hex Bytes / ASCII
                  </span>
                </div>
                <button
                  onClick={handleCopyText}
                  className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 font-medium flex items-center gap-1 transition-colors"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy Hex'}</span>
                </button>
              </div>

              <div className="p-4 max-h-[500px] overflow-y-auto font-mono text-xs leading-5 bg-white text-slate-800 border-t border-slate-100">
                <pre className="whitespace-pre font-mono text-slate-800 select-text">
                  {file.preview_text || 'No hex dump available.'}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 px-6 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500">
          <div>
            Click <strong>Analyze in Sandbox</strong> to perform deep static & behavioral triage on this carved file.
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 font-semibold cursor-pointer shadow-2xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
