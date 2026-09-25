import React, { useState } from 'react';
import { Header } from './components/Header';
import { FileUpload } from './components/FileUpload';
import { AnalysisDashboard } from './components/AnalysisDashboard';
import { DisclaimerModal } from './components/DisclaimerModal';
import { apiClient } from './api/client';

export const App: React.FC = () => {
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isDisclaimerOpen, setIsDisclaimerOpen] = useState(false);

  const handleUpload = async (files: File[]) => {
    setIsUploading(true);
    try {
      const res = await apiClient.uploadFiles(files);
      if (res.jobs && res.jobs.length > 0) {
        // Set first job as active
        setActiveJobId(res.jobs[0].job_id);
      }
    } catch (err: any) {
      alert(err.message || 'File upload failed');
    } finally {
      setIsUploading(false);
    }
  };

  const handleReset = () => {
    setActiveJobId(null);
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 font-sans text-slate-900">
      <Header
        onOpenDisclaimer={() => setIsDisclaimerOpen(true)}
        onReset={handleReset}
      />

      <main className="flex-1">
        {activeJobId ? (
          <AnalysisDashboard
            jobId={activeJobId}
            onBack={handleReset}
          />
        ) : (
          <FileUpload
            onUpload={handleUpload}
            isUploading={isUploading}
          />
        )}
      </main>

      <footer className="border-t border-slate-200 bg-white py-6">
        <div className="max-w-7xl mx-auto px-4 text-center text-xs text-slate-500 space-y-1 font-mono">
          <p className="font-semibold text-slate-700">FileSanitizer — Content Disarm & Reconstruction</p>
          <p className="text-slate-400">
            Automated analysis and sanitization reduce threat surface. Never execute untrusted files.
          </p>
        </div>
      </footer>

      <DisclaimerModal
        isOpen={isDisclaimerOpen}
        onClose={() => setIsDisclaimerOpen(false)}
      />
    </div>
  );
};

export default App;
