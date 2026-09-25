import React, { useState } from 'react';
import { Header, ViewTab } from './components/Header';
import { FileUpload } from './components/FileUpload';
import { AnalysisDashboard } from './components/AnalysisDashboard';
import { HowItWorks } from './components/HowItWorks';
import { SupportedFormats } from './components/SupportedFormats';
import { DisclaimerModal } from './components/DisclaimerModal';
import { apiClient } from './api/client';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<ViewTab>('sanitizer');
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isDisclaimerOpen, setIsDisclaimerOpen] = useState(false);

  const handleUpload = async (files: File[]) => {
    setIsUploading(true);
    try {
      const res = await apiClient.uploadFiles(files);
      if (res.jobs && res.jobs.length > 0) {
        setActiveJobId(res.jobs[0].job_id);
        setCurrentView('sanitizer');
      }
    } catch (err: any) {
      alert(err.message || 'File upload failed');
    } finally {
      setIsUploading(false);
    }
  };

  const handleUrlFetchSuccess = (jobId: string) => {
    setActiveJobId(jobId);
    setCurrentView('sanitizer');
  };

  const handleReset = () => {
    setActiveJobId(null);
    setCurrentView('sanitizer');
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 font-sans text-slate-900">
      <Header
        currentView={currentView}
        onNavigate={(view) => {
          setCurrentView(view);
        }}
        onOpenDisclaimer={() => setIsDisclaimerOpen(true)}
        onReset={handleReset}
      />

      <main className="flex-1">
        {currentView === 'how-it-works' ? (
          <HowItWorks 
            onGoToSanitizer={() => { setActiveJobId(null); setCurrentView('sanitizer'); }}
            onGoToFormats={() => setCurrentView('supported-formats')}
          />
        ) : currentView === 'supported-formats' ? (
          <SupportedFormats 
            onGoToSanitizer={() => { setActiveJobId(null); setCurrentView('sanitizer'); }}
          />
        ) : activeJobId ? (
          <AnalysisDashboard
            jobId={activeJobId}
            onBack={handleReset}
          />
        ) : (
          <FileUpload
            onUpload={handleUpload}
            onUrlFetchSuccess={handleUrlFetchSuccess}
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
