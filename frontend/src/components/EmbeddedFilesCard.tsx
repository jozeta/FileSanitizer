import React, { useState, useMemo } from 'react';
import {
  Layers,
  FileCode,
  Download,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Search,
  ExternalLink,
  Copy,
  Check,
  RefreshCw,
  FileText,
  FileArchive,
  Cpu,
  Mail
} from 'lucide-react';
import { EmbeddedFileItem } from '../types';
import { apiClient } from '../api/client';
import { formatBytes, truncateHash } from '../utils/formatters';
import { findReferencedJob } from '../utils/crossFileReferences';

interface EmbeddedFilesCardProps {
  jobId: string;
  embeddedFiles: EmbeddedFileItem[];
  onSelectJob?: (newJobId: string) => void;
  workspaceJobs?: any[];
}

export const EmbeddedFilesCard: React.FC<EmbeddedFilesCardProps> = ({
  jobId,
  embeddedFiles = [],
  onSelectJob,
  workspaceJobs,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'dangerous' | 'safe'>('all');
  const [analyzingIds, setAnalyzingIds] = useState<Record<number, boolean>>({});
  const [analyzedSuccess, setAnalyzedSuccess] = useState<Record<number, { jobId: string; filename: string }>>({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Statistics
  const dangerousCount = useMemo(
    () => embeddedFiles.filter((f) => f.is_dangerous).length,
    [embeddedFiles]
  );
  const safeCount = embeddedFiles.length - dangerousCount;
  const totalBytes = useMemo(
    () => embeddedFiles.reduce((acc, f) => acc + (f.size || 0), 0),
    [embeddedFiles]
  );

  // Filtered files
  const filteredFiles = useMemo(() => {
    return embeddedFiles.filter((f) => {
      if (filterType === 'dangerous' && !f.is_dangerous) return false;
      if (filterType === 'safe' && f.is_dangerous) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        f.name.toLowerCase().includes(q) ||
        (f.origin_stream && f.origin_stream.toLowerCase().includes(q)) ||
        (f.parent_format && f.parent_format.toLowerCase().includes(q)) ||
        (f.mime_type && f.mime_type.toLowerCase().includes(q)) ||
        (f.sha256 && f.sha256.toLowerCase().includes(q))
      );
    });
  }, [embeddedFiles, filterType, searchQuery]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleAnalyze = async (file: EmbeddedFileItem) => {
    setAnalyzingIds((prev) => ({ ...prev, [file.id]: true }));
    setActionError(null);
    try {
      const res = await apiClient.analyzeEmbeddedFile(jobId, file.id);
      setAnalyzedSuccess((prev) => ({
        ...prev,
        [file.id]: { jobId: res.job_id, filename: res.filename },
      }));
      // If user wants immediate navigation and onSelectJob is provided:
      if (onSelectJob && res.job_id) {
        onSelectJob(res.job_id);
      }
    } catch (err: any) {
      setActionError(err.message || `Failed to analyze embedded file '${file.name}'`);
    } finally {
      setAnalyzingIds((prev) => ({ ...prev, [file.id]: false }));
    }
  };

  const getFormatIcon = (format: string, name: string) => {
    const fLower = (format || '').toLowerCase();
    const nLower = (name || '').toLowerCase();
    if (fLower.includes('pdf') || nLower.endsWith('.pdf')) {
      return <FileText className="w-5 h-5 text-rose-600" />;
    }
    if (fLower.includes('office') || ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm'].some(ext => nLower.endsWith(ext))) {
      return <FileCode className="w-5 h-5 text-blue-600" />;
    }
    if (fLower.includes('executable') || fLower.includes('binary') || ['.exe', '.dll', '.bin'].some(ext => nLower.endsWith(ext))) {
      return <Cpu className="w-5 h-5 text-purple-600" />;
    }
    if (fLower.includes('email') || ['.eml', '.msg'].some(ext => nLower.endsWith(ext))) {
      return <Mail className="w-5 h-5 text-indigo-600" />;
    }
    if (fLower.includes('archive') || ['.zip', '.tar', '.gz', '.7z'].some(ext => nLower.endsWith(ext))) {
      return <FileArchive className="w-5 h-5 text-amber-600" />;
    }
    return <FileCode className="w-5 h-5 text-slate-600" />;
  };

  if (!embeddedFiles || embeddedFiles.length === 0) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Layers className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <h4 className="text-sm font-bold text-slate-800">No Embedded Files Discovered</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
          No nested attachments, OLE package embeddings, or secondary binary objects were detected inside this document.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-100 mb-5 gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-purple-50 text-purple-600 rounded-2xl border border-purple-100 text-lg">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Embedded Files & Extracted Payloads ({embeddedFiles.length})
              </h3>
              <p className="text-xs text-slate-500">
                Extracted nested objects from PDF catalog attachments, Office OLE package streams, and PE resources.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {dangerousCount > 0 ? (
              <span className="px-3 py-1 bg-rose-50 text-rose-800 border border-rose-200 rounded-full text-xs font-bold flex items-center gap-1.5 animate-pulse">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                {dangerousCount} Dangerous Payload{dangerousCount > 1 ? 's' : ''}
              </span>
            ) : (
              <span className="px-3 py-1 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                All Embedded Files Benign
              </span>
            )}
            <span className="px-3 py-1 bg-slate-100 text-slate-700 border border-slate-200 rounded-full text-xs font-mono">
              Total Size: {formatBytes(totalBytes)}
            </span>
          </div>
        </div>

        {/* Action Error Banner */}
        {actionError && (
          <div className="mb-4 p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 flex items-center justify-between">
            <span className="font-semibold">⚠️ {actionError}</span>
            <button
              onClick={() => setActionError(null)}
              className="text-slate-400 hover:text-slate-600 font-bold ml-2 cursor-pointer"
            >
              ×
            </button>
          </div>
        )}

        {/* Filter and Search Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by file name, origin stream, MIME type, or SHA-256..."
              className="w-full pl-9 pr-4 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono shadow-xs"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl text-xs font-semibold">
            <button
              onClick={() => setFilterType('all')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                filterType === 'all'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All ({embeddedFiles.length})
            </button>
            <button
              onClick={() => setFilterType('dangerous')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                filterType === 'dangerous'
                  ? 'bg-white text-rose-700 shadow-sm font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Dangerous ({dangerousCount})
            </button>
            <button
              onClick={() => setFilterType('safe')}
              className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                filterType === 'safe'
                  ? 'bg-white text-emerald-700 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Benign ({safeCount})
            </button>
          </div>
        </div>
      </div>

      {/* Embedded Files List */}
      <div className="space-y-3">
        {filteredFiles.map((file) => {
          const isAnalyzing = Boolean(analyzingIds[file.id]);
          const analyzedInfo = analyzedSuccess[file.id];
          const matchedJob = (() => {
            if (!workspaceJobs || workspaceJobs.length === 0) return null;
            return findReferencedJob(file.name, workspaceJobs, jobId) ||
              (file.sha256 ? findReferencedJob(file.sha256, workspaceJobs, jobId) : null) ||
              (file.md5 ? findReferencedJob(file.md5, workspaceJobs, jobId) : null);
          })();

          return (
            <div
              key={file.id}
              className={`bg-white rounded-2xl border p-5 transition-all shadow-xs ${
                file.is_dangerous
                  ? 'border-rose-300 bg-rose-50/20'
                  : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                {/* File Info */}
                <div className="flex items-start gap-3 min-w-0 flex-1">
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl shrink-0">
                    {getFormatIcon(file.parent_format, file.name)}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      {matchedJob ? (
                        <button
                          type="button"
                          onClick={() => onSelectJob && onSelectJob(matchedJob.jobId)}
                          className="text-sm font-bold text-indigo-700 hover:text-indigo-900 hover:underline truncate font-mono flex items-center gap-1.5 cursor-pointer text-left"
                          title={`Click to open analyzed file '${matchedJob.filename}'`}
                        >
                          <span>{file.name}</span>
                          <ExternalLink className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-100 text-indigo-800 border border-indigo-200 font-sans">
                            Analyzed ({matchedJob.filename})
                          </span>
                        </button>
                      ) : (
                        <h4 className="text-sm font-bold text-slate-900 truncate font-mono">
                          {file.name}
                        </h4>
                      )}

                      {file.is_dangerous ? (
                        <span className="px-2.5 py-0.5 bg-rose-100 text-rose-800 border border-rose-200 rounded-full text-[10px] font-bold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-rose-600" />
                          High Risk Payload
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 bg-emerald-100 text-emerald-800 border border-emerald-200 rounded-full text-[10px] font-semibold">
                          Benign Object
                        </span>
                      )}

                      <span className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded-md text-[10px] font-mono">
                        {file.size_formatted}
                      </span>

                      <span className="px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded-md text-[10px] font-mono">
                        {file.mime_type}
                      </span>
                    </div>

                    {/* Threat Reason if dangerous */}
                    {file.threat_reason && (
                      <p className="text-xs text-rose-700 font-medium mb-1.5 flex items-center gap-1">
                        <span>⚠️ Threat:</span>
                        <span>{file.threat_reason}</span>
                      </p>
                    )}

                    {/* Origin stream details */}
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 font-mono">
                      <span>Parent: <strong className="text-slate-700 font-sans">{file.parent_format}</strong></span>
                      {file.origin_stream && (
                        <span>Stream: <span className="text-slate-600">{file.origin_stream}</span></span>
                      )}
                    </div>

                    {/* Hashes */}
                    <div className="flex flex-wrap items-center gap-3 mt-2 text-[11px] font-mono text-slate-500">
                      <div className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                        <span className="text-slate-400">SHA-256:</span>
                        <span className="text-slate-800 font-semibold">{truncateHash(file.sha256, 10)}</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(file.sha256)}
                          className="text-slate-400 hover:text-slate-600 cursor-pointer ml-1"
                          title="Copy SHA-256 hash"
                        >
                          {copiedHash === file.sha256 ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>

                      {file.md5 && (
                        <div className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                          <span className="text-slate-400">MD5:</span>
                          <span className="text-slate-800">{truncateHash(file.md5, 8)}</span>
                          <button
                            type="button"
                            onClick={() => handleCopy(file.md5)}
                            className="text-slate-400 hover:text-slate-600 cursor-pointer ml-1"
                            title="Copy MD5 hash"
                          >
                            {copiedHash === file.md5 ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Actions: Download & Analyze as New Job */}
                <div className="flex items-center gap-2 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-100">
                  {/* Download Button */}
                  <a
                    href={apiClient.getEmbeddedFileDownloadUrl(jobId, file.id)}
                    download={file.name}
                    className="px-3.5 py-2 bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 text-xs font-semibold rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer shadow-xs"
                    title={`Download extracted file payload '${file.name}'`}
                  >
                    <Download className="w-3.5 h-3.5 text-slate-500" />
                    <span>Download</span>
                  </a>

                  {/* Analyze as New Job Button or View Analyzed File */}
                  {matchedJob ? (
                    <button
                      type="button"
                      onClick={() => onSelectJob && onSelectJob(matchedJob.jobId)}
                      className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer shadow-xs"
                      title={`Switch to analyzed workspace file '${matchedJob.filename}'`}
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>View Analyzed File ({matchedJob.filename})</span>
                    </button>
                  ) : analyzedInfo ? (
                    <button
                      type="button"
                      onClick={() => onSelectJob && onSelectJob(analyzedInfo.jobId)}
                      className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer shadow-xs"
                      title="Switch to analyzed child job"
                    >
                      <Check className="w-3.5 h-3.5" />
                      <span>View Analysis ↗</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => handleAnalyze(file)}
                      disabled={isAnalyzing}
                      className="px-3.5 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer shadow-xs"
                      title="Submit this extracted embedded file for a dedicated analysis pipeline"
                    >
                      {isAnalyzing ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <ExternalLink className="w-3.5 h-3.5" />
                      )}
                      <span>{isAnalyzing ? 'Submitting...' : 'Analyze as New Job'}</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}

        {filteredFiles.length === 0 && (
          <div className="bg-white rounded-2xl border border-slate-200 p-8 text-center">
            <p className="text-xs text-slate-400 italic">No embedded files match your current filter or search criteria.</p>
          </div>
        )}
      </div>
    </div>
  );
};
