import React, { useState, useEffect } from 'react';
import { Copy, Check, ArrowLeft, RefreshCw, FileText, Globe, Shield, Sparkles, AlertCircle } from 'lucide-react';
import { JobDetail, SanitizationOptions } from '../types';
import { apiClient } from '../api/client';
import { formatBytes, truncateHash } from '../utils/formatters';
import { SecurityCard } from './SecurityCard';
import { MetadataViewer } from './MetadataViewer';
import { UrlExplorer } from './UrlExplorer';
import { SanitizationPanel } from './SanitizationPanel';
import { ValidationComparison } from './ValidationComparison';
import { MacroWarningBanner } from './MacroWarningBanner';

interface AnalysisDashboardProps {
  jobId: string;
  onBack: () => void;
}

export const AnalysisDashboard: React.FC<AnalysisDashboardProps> = ({ jobId, onBack }) => {
  const [job, setJob] = useState<JobDetail | null>(null);
  const [activeTab, setActiveTab] = useState<'security' | 'metadata' | 'urls' | 'sanitize' | 'result'>('security');
  const [copiedHash, setCopiedHash] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  // Poll job status until done or during processing
  useEffect(() => {
    let interval: any = null;

    const fetchDetails = async () => {
      try {
        const fullJob = await apiClient.getJobAnalysis(jobId);
        // Also fetch metadata & URLs if analyzed
        if (fullJob.state !== 'QUEUED' && fullJob.state !== 'ANALYZING') {
          const [meta, urlData] = await Promise.all([
            apiClient.getJobMetadata(jobId).catch(() => undefined),
            apiClient.getJobUrls(jobId).catch(() => ({ urls: [] })),
          ]);
          fullJob.metadata = meta;
          fullJob.urls = urlData.urls;

          if (fullJob.state === 'COMPLETED') {
            const res = await apiClient.getJobResult(jobId).catch(() => undefined);
            if (res && res.validation) {
              fullJob.validation = res.validation;
            }
          }
        }

        setJob(fullJob);

        if (fullJob.state === 'COMPLETED' || fullJob.state === 'FAILED' || fullJob.state === 'ANALYZED') {
          setIsProcessing(false);
        }
      } catch (err) {
        console.error('Error fetching job details:', err);
      }
    };

    fetchDetails();

    interval = setInterval(() => {
      fetchDetails();
    }, 2000);

    return () => clearInterval(interval);
  }, [jobId]);

  const copySha256 = () => {
    if (job?.hashes?.sha256) {
      navigator.clipboard.writeText(job.hashes.sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  const handleSanitize = async (profile: string, customOptions?: SanitizationOptions) => {
    setIsProcessing(true);
    try {
      await apiClient.startSanitization(jobId, profile, customOptions);
      setActiveTab('sanitize');
    } catch (err: any) {
      alert(err.message || 'Sanitization request failed');
      setIsProcessing(false);
    }
  };

  const handleDownload = () => {
    window.location.href = apiClient.getDownloadUrl(jobId);
  };

  const handleDownloadReport = () => {
    window.location.href = apiClient.getReportUrl(jobId);
  };

  if (!job) {
    return (
      <div className="max-w-5xl mx-auto py-20 px-4 text-center">
        <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-4" />
        <p className="text-sm text-slate-600 font-mono">Loading job workspace...</p>
      </div>
    );
  }

  const isAnalyzing = job.state === 'QUEUED' || job.state === 'ANALYZING';
  const isSanitizing = job.state === 'SANITIZING' || job.state === 'VALIDATING';
  const isCompleted = job.state === 'COMPLETED';
  const isFailed = job.state === 'FAILED';
  const hasMacros = job.findings?.some(f => f.category === 'macro') || false;

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 sm:px-6">
      {/* Back Button */}
      <button
        onClick={onBack}
        className="inline-flex items-center gap-2 text-xs font-semibold text-slate-500 hover:text-slate-900 mb-6 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Upload another file</span>
      </button>

      {/* Top File Summary Header */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-7 shadow-sm mb-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5 mb-1.5 flex-wrap">
              <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight truncate">
                {job.filename}
              </h2>
              <span className="px-2.5 py-0.5 bg-slate-100 text-slate-700 text-xs font-mono font-medium rounded-full border border-slate-200 uppercase">
                {job.category}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 font-mono">
              <span>Size: {formatBytes(job.file_size)}</span>
              <span>MIME: {job.mime_type}</span>
              {job.signature_description && (
                <span>Signature: {job.signature_description}</span>
              )}
            </div>
          </div>

          {/* Cryptographic SHA-256 with Copy Action */}
          {job.hashes?.sha256 && (
            <div className="flex items-center gap-2 bg-slate-50 p-2.5 rounded-2xl border border-slate-200/80 self-start md:self-auto">
              <div className="text-right">
                <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block">
                  SHA-256 Identification Hash
                </span>
                <span className="text-xs font-mono font-semibold text-slate-800">
                  {truncateHash(job.hashes.sha256, 12, 12)}
                </span>
              </div>
              <button
                onClick={copySha256}
                className="p-2 rounded-xl text-slate-500 hover:text-slate-900 hover:bg-white transition-colors cursor-pointer"
                title="Copy full SHA-256 hash"
              >
                {copiedHash ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          )}
        </div>

        {/* Processing Progress Bar */}
        {(isAnalyzing || isSanitizing) && (
          <div className="mt-5 pt-4 border-t border-slate-100">
            <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-2">
              <span className="flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-600" />
                <span>
                  {isAnalyzing ? 'Conducting Deep Security Analysis & Scanner Inspection...' :
                   'Performing Content Disarm & Reconstruction (CDR)...'}
                </span>
              </span>
              <span className="font-bold">{job.progress}%</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${job.progress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Prominent Macro Warning Banner */}
      {hasMacros && (
        <MacroWarningBanner
          macroDetails={job.findings?.find(f => f.category === 'macro')?.details?.findings}
        />
      )}

      {/* Failure Banner */}
      {isFailed && (
        <div className="mb-6 p-5 bg-rose-50 border border-rose-200 rounded-2xl flex items-start gap-3 text-rose-900">
          <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-bold text-sm">Processing Encountered an Error</h4>
            <p className="text-xs mt-1 text-rose-800 leading-relaxed font-mono">
              {job.error_message || 'Operation failed during pipeline execution.'}
            </p>
          </div>
        </div>
      )}

      {/* Section Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-3 mb-6 overflow-x-auto">
        <button
          onClick={() => setActiveTab('security')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'security'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Security Analysis</span>
          {job.findings && job.findings.length > 0 && (
            <span className="px-1.5 py-0.2 bg-white/20 rounded-full text-[10px]">
              {job.findings.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('metadata')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'metadata'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Metadata ({job.metadata?.total_fields || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('urls')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'urls'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Discovered URLs ({job.urls?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('sanitize')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
            activeTab === 'sanitize'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-blue-700 bg-blue-50 hover:bg-blue-100'
          }`}
        >
          <Sparkles className="w-4 h-4" />
          <span>Sanitization & CDR</span>
        </button>

        {isCompleted && (
          <button
            onClick={() => setActiveTab('result')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'result'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-emerald-700 bg-emerald-50 hover:bg-emerald-100'
            }`}
          >
            <span>Clean File & Validation</span>
          </button>
        )}
      </div>

      {/* Active Tab View */}
      <div>
        {activeTab === 'security' && (
          <SecurityCard
            risk={job.risk}
            clamav={job.clamav as any}
            findings={job.findings}
          />
        )}

        {activeTab === 'metadata' && (
          <MetadataViewer metadata={job.metadata} />
        )}

        {activeTab === 'urls' && (
          <UrlExplorer urls={job.urls} />
        )}

        {activeTab === 'sanitize' && (
          <div className="space-y-6">
            <SanitizationPanel
              category={job.category}
              isProcessing={isSanitizing || isProcessing}
              onSanitize={handleSanitize}
              suggestedProfile={job.risk?.suggested_profile}
              isMalicious={job.risk?.level === 'MALICIOUS'}
            />

            {/* If completed, also preview validation below */}
            {isCompleted && job.validation && (
              <ValidationComparison
                validation={job.validation}
                sanitizedFilename={job.filename}
                onDownload={handleDownload}
                onDownloadReport={handleDownloadReport}
                warnings={job.validation.warnings}
              />
            )}
          </div>
        )}

        {activeTab === 'result' && isCompleted && job.validation && (
          <ValidationComparison
            validation={job.validation}
            sanitizedFilename={job.filename}
            onDownload={handleDownload}
            onDownloadReport={handleDownloadReport}
            warnings={job.validation.warnings}
          />
        )}
      </div>
    </div>
  );
};
