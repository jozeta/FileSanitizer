import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import { UploadCloud, File, X, AlertCircle, ArrowRight, Shield } from 'lucide-react';
import { formatBytes } from '../utils/formatters';

interface FileUploadProps {
  onUpload: (files: File[]) => void;
  isUploading: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onUpload, isUploading }) => {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    setError(null);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      addFiles(Array.from(e.dataTransfer.files));
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      addFiles(Array.from(e.target.files));
    }
  };

  const addFiles = (newFiles: File[]) => {
    // 100MB limit per file check
    const maxBytes = 100 * 1024 * 1024;
    const oversized = newFiles.filter(f => f.size > maxBytes);
    if (oversized.length > 0) {
      setError(`File "${oversized[0].name}" exceeds the maximum upload limit of 100 MB.`);
      return;
    }
    setSelectedFiles(prev => [...prev, ...newFiles]);
  };

  const removeFile = (index: number) => {
    setSelectedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleStart = () => {
    if (selectedFiles.length > 0) {
      onUpload(selectedFiles);
    }
  };

  return (
    <div className="max-w-3xl mx-auto py-12 px-4">
      {/* Hero Title */}
      <div className="text-center mb-8">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight mb-2">
          FileSanitizer
        </h1>
        <p className="text-base sm:text-lg text-slate-600 font-normal">
          Clean files before you share them.
        </p>
      </div>

      {/* Drop Zone Box */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-3xl p-10 sm:p-14 text-center cursor-pointer transition-all duration-200 bg-white ${
          isDragOver
            ? 'border-blue-500 bg-blue-50/50 scale-[1.01]'
            : 'border-slate-300 hover:border-slate-400 hover:bg-slate-50/50 shadow-sm'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="w-16 h-16 rounded-2xl bg-blue-50 text-blue-600 mx-auto flex items-center justify-center mb-5">
          <UploadCloud className="w-8 h-8" />
        </div>

        <h3 className="text-lg font-semibold text-slate-900 mb-1">
          Drop files here
        </h3>
        <p className="text-sm text-slate-500 mb-4">
          or click to browse from your device
        </p>

        <div className="inline-flex items-center gap-2 px-3 py-1 bg-slate-100 rounded-full text-xs font-mono text-slate-600">
          <Shield className="w-3.5 h-3.5 text-slate-400" />
          <span>Max 100 MB per file · Never overwritten · Auto-purged</span>
        </div>
      </div>

      {/* Format Badges */}
      <div className="mt-4 text-center text-xs text-slate-500">
        <span className="font-medium text-slate-700">Supported formats: </span>
        <span className="font-mono">PDF · Office (DOCX, XLSX, PPTX) · Images (JPEG, PNG, GIF, WEBP) · SVG · HTML · Archives</span>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mt-4 p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
          <span>{error}</span>
        </div>
      )}

      {/* Staged Files List */}
      {selectedFiles.length > 0 && (
        <div className="mt-8 bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-100">
            <h4 className="text-sm font-semibold text-slate-800">
              Files queued for analysis ({selectedFiles.length})
            </h4>
            <button
              onClick={() => setSelectedFiles([])}
              className="text-xs text-slate-500 hover:text-rose-600 font-medium transition-colors"
            >
              Clear all
            </button>
          </div>

          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {selectedFiles.map((file, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2.5 bg-slate-50 hover:bg-slate-100 rounded-xl border border-slate-100 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-slate-500 shrink-0">
                    <File className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-900 truncate max-w-xs sm:max-w-md">
                      {file.name}
                    </p>
                    <p className="text-xs text-slate-500 font-mono">
                      {formatBytes(file.size)}
                    </p>
                  </div>
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    removeFile(idx);
                  }}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors"
                  title="Remove file"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>

          <div className="mt-5 pt-3 border-t border-slate-100 flex items-center justify-end">
            <button
              onClick={handleStart}
              disabled={isUploading}
              className="px-6 py-2.5 bg-slate-900 hover:bg-blue-600 text-white font-medium text-sm rounded-xl shadow-sm transition-all duration-200 flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <span>{isUploading ? 'Uploading & Analyzing...' : 'Analyze Files'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
