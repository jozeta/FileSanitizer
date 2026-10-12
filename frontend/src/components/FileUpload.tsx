import React, { useState, useRef, useEffect, DragEvent, ChangeEvent } from 'react';
import { 
  UploadCloud, 
  File, 
  X, 
  AlertCircle, 
  ArrowRight, 
  Shield, 
  Globe, 
  Lock, 
  ShieldAlert, 
  Loader2,
  CheckCircle2
} from 'lucide-react';
import { formatBytes } from '../utils/formatters';
import { apiClient } from '../api/client';

interface FileUploadProps {
  onUpload: (files: File[]) => void;
  onUrlFetchSuccess?: (jobId: string) => void;
  isUploading: boolean;
  uploadProgress?: { loaded: number; total: number; percentage: number } | null;
}

export const FileUpload: React.FC<FileUploadProps> = ({ 
  onUpload, 
  onUrlFetchSuccess,
  isUploading,
  uploadProgress
}) => {
  const [mode, setMode] = useState<'upload' | 'url'>('upload');
  
  // File upload state
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auto-clear staged file when upload completes
  useEffect(() => {
    if (!isUploading) {
      setSelectedFiles([]);
    }
  }, [isUploading]);

  // URL fetch state
  const [inputUrl, setInputUrl] = useState<string>('');
  const [isFetchingUrl, setIsFetchingUrl] = useState<boolean>(false);
  const [urlFetchStatus, setUrlFetchStatus] = useState<string | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const startFilesProcessing = (files: File[]) => {
    const maxBytes = 100 * 1024 * 1024;
    for (const file of files) {
      if (file.size > maxBytes) {
        setError(`File "${file.name}" exceeds the maximum upload limit of 100 MB.`);
        return;
      }
    }
    setError(null);
    setSelectedFiles(files);
    onUpload(files);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    setError(null);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      startFilesProcessing(Array.from(e.dataTransfer.files));
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const files = Array.from(e.target.files);
      e.target.value = '';
      startFilesProcessing(files);
    }
  };

  const removeFile = () => {
    setSelectedFiles([]);
  };

  const handleStartUpload = () => {
    if (selectedFiles.length > 0) {
      onUpload(selectedFiles);
    }
  };

  const handleFetchUrl = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanUrl = inputUrl.trim();
    if (!cleanUrl) {
      setUrlError('Please enter a valid remote file URL.');
      return;
    }

    setUrlError(null);
    setIsFetchingUrl(true);
    setUrlFetchStatus('Checking SSRF security & threat watchlists...');

    try {
      const res = await apiClient.fetchUrl(cleanUrl);
      setUrlFetchStatus('File fetched successfully! Starting analysis...');
      if (res.jobs && res.jobs.length > 0 && onUrlFetchSuccess) {
        onUrlFetchSuccess(res.jobs[0].job_id);
      }
    } catch (err: any) {
      setUrlError(err.message || 'Failed to fetch and analyze file from URL.');
      setUrlFetchStatus(null);
    } finally {
      setIsFetchingUrl(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto py-10 px-4">
      {/* Hero Title */}
      <div className="text-center mb-8">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight mb-2">
          FileSanitizer
        </h1>
        <p className="text-base sm:text-lg text-slate-600 font-normal">
          Clean files before you share them.
        </p>

        {/* Ingestion Mode Toggle */}
        <div className="inline-flex p-1 bg-slate-100 rounded-2xl border border-slate-200 mt-6 shadow-xs">
          <button
            type="button"
            onClick={() => { setMode('upload'); setError(null); }}
            className={`flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              mode === 'upload'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload Local Files</span>
          </button>

          <button
            type="button"
            onClick={() => { setMode('url'); setUrlError(null); }}
            className={`flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              mode === 'url'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Globe className="w-4 h-4 text-blue-600" />
            <span>Check Domain or IP</span>
          </button>
        </div>
      </div>

      {mode === 'upload' ? (
        /* ================= MODE: LOCAL FILE UPLOAD ================= */
        <>
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
              Drop file(s) here to analyze immediately
            </h3>
            <p className="text-sm text-slate-500 mb-4">
              or click to browse • supports single files or multiple EVTX logs for unified timeline
            </p>

            <div className="inline-flex items-center gap-2 px-3 py-1 bg-slate-100 rounded-full text-xs font-mono text-slate-600">
              <Shield className="w-3.5 h-3.5 text-slate-400" />
              <span>Max 100 MB · Single file isolation · Auto-purged</span>
            </div>
          </div>

          {/* Format Badges */}
          <div className="mt-4 text-center text-xs text-slate-500">
            <span className="font-medium text-slate-700">Supported formats: </span>
            <span className="font-mono">PDF · Office (DOCX, XLSX, PPTX, RTF) · Images · SVG · HTML · Archives · Emails · Executables · Scripts</span>
          </div>

          {/* Upload Error */}
          {error && (
            <div className="mt-4 p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-sm flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{error}</span>
            </div>
          )}

          {/* Staged File Card */}
          {selectedFiles.length > 0 && (
            <div className="mt-8 bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-100">
                <h4 className="text-sm font-semibold text-slate-800">
                  File queued for analysis
                </h4>
                <button
                  onClick={() => setSelectedFiles([])}
                  className="text-xs text-slate-500 hover:text-rose-600 font-medium transition-colors cursor-pointer"
                >
                  Clear file
                </button>
              </div>

              <div className="space-y-2">
                {selectedFiles.map((file, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-3 bg-slate-50 hover:bg-slate-100 rounded-xl border border-slate-100 transition-colors"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shrink-0">
                        <File className="w-5 h-5" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-slate-900 truncate max-w-xs sm:max-w-md">
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
                        removeFile();
                      }}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors cursor-pointer"
                      title="Remove file"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>

              {/* Upload Progress Bar */}
              {isUploading && (
                <div className="mt-4 p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 animate-overlay-fade">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="font-semibold text-slate-700 flex items-center gap-2">
                      <Loader2 className="w-3.5 h-3.5 text-blue-600 animate-spin" />
                      <span>Uploading File to Isolated Workspace...</span>
                    </span>
                    <span className="font-bold text-blue-600">
                      {uploadProgress ? `${uploadProgress.percentage}%` : 'Uploading...'}
                    </span>
                  </div>

                  <div className="w-full bg-slate-200 h-2.5 rounded-full overflow-hidden">
                    <div
                      className="bg-blue-600 h-full rounded-full transition-all duration-150 ease-out"
                      style={{ width: `${uploadProgress ? uploadProgress.percentage : 15}%` }}
                    />
                  </div>

                  {uploadProgress && uploadProgress.total > 0 && (
                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                      <span>{formatBytes(uploadProgress.loaded)} / {formatBytes(uploadProgress.total)}</span>
                      <span>{uploadProgress.percentage < 100 ? `${uploadProgress.percentage}% uploaded` : 'Processing upload...'}</span>
                    </div>
                  )}
                </div>
              )}

              <div className="mt-5 pt-3 border-t border-slate-100 flex items-center justify-end">
                <button
                  onClick={handleStartUpload}
                  disabled={isUploading}
                  className="px-6 py-2.5 bg-slate-900 hover:bg-blue-600 text-white font-medium text-sm rounded-xl shadow-sm transition-all duration-200 flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {isUploading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>{uploadProgress && uploadProgress.total > 0 ? `Uploading (${uploadProgress.percentage}%)` : 'Uploading...'}</span>
                    </>
                  ) : (
                    <>
                      <span>Analyze File</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        /* ================= MODE: REMOTE URL FILE FETCHER ================= */
        <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-10 shadow-sm space-y-6">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center shrink-0 border border-blue-100">
              <Globe className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-slate-900">Fetch File, Inspect Domain or Analyze IP</h3>
              <p className="text-xs sm:text-sm text-slate-600 font-normal mt-0.5">
                Submit any domain (e.g. <span className="font-mono text-blue-700">example.com</span>) or IP to capture a live sandboxed screenshot thumbnail, query WHOIS/RDAP, and run deep DNS records analysis, or submit a direct file URL to download and analyze safely.
              </p>
            </div>
          </div>

          <form onSubmit={handleFetchUrl} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-700 uppercase tracking-wider">
                Remote URL, Domain, or IP Address
              </label>
              <div className="relative">
                <input
                  type="text"
                  placeholder="e.g. example.com, 1.1.1.1, or https://example.com/payload.exe"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  disabled={isFetchingUrl}
                  className="w-full pl-4 pr-32 py-3 text-sm bg-slate-50 border border-slate-300 rounded-2xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white font-mono text-slate-800 disabled:opacity-50"
                />
                <button
                  type="submit"
                  disabled={isFetchingUrl || !inputUrl.trim()}
                  className="absolute right-1.5 top-1.5 bottom-1.5 px-4 bg-slate-900 hover:bg-blue-600 text-white text-xs font-semibold rounded-xl transition-colors disabled:opacity-40 flex items-center gap-1.5 cursor-pointer"
                >
                  {isFetchingUrl ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Fetching...</span>
                    </>
                  ) : (
                    <>
                      <span>Fetch & Inspect</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Fetch Status Notice */}
            {urlFetchStatus && (
              <div className="p-3 bg-blue-50/70 border border-blue-200 rounded-xl text-blue-900 text-xs flex items-center gap-2 font-medium">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-600 shrink-0" />
                <span>{urlFetchStatus}</span>
              </div>
            )}

            {/* URL Error Alert */}
            {urlError && (
              <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-900 text-xs flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold">Security / Fetch Error:</span> {urlError}
                </div>
              </div>
            )}

            {/* SSRF & Watchlist Guarantees Box */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                  <Lock className="w-3.5 h-3.5 text-blue-600" />
                  <span>Anti-SSRF Protection</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed">
                  Recursive DNS checks block private subnets, cloud metadata (169.254.169.254), and loopbacks.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                  <ShieldAlert className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Watchlist Screening</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed">
                  Pre-download reputation checks reject known URLhaus and VirusTotal malware/scam hosts.
                </p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
                  <CheckCircle2 className="w-3.5 h-3.5 text-purple-600" />
                  <span>Format Verification</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed">
                  Only supported files (PDF, Office, Images, Archives, SVG, HTML) are ingested and disarmed.
                </p>
              </div>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
