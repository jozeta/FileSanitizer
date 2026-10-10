import React, { useState, useEffect, useRef } from 'react';
import { Header, ViewTab } from './components/Header';
import { FileUpload } from './components/FileUpload';
import { AnalysisDashboard } from './components/AnalysisDashboard';
import { RelationshipMappingView } from './components/RelationshipMappingView';
import { WorkspaceTabBar } from './components/WorkspaceTabBar';
import { HowItWorks } from './components/HowItWorks';
import { SupportedFormats } from './components/SupportedFormats';
import { SettingsView } from './components/SettingsView';
import { DisclaimerModal } from './components/DisclaimerModal';
import { UploadProgressModal } from './components/UploadProgressModal';
import { DragDropOverlay } from './components/DragDropOverlay';
import { ErrorBoundary } from './components/ErrorBoundary';
import { AlertTriangle, Info } from 'lucide-react';
import { apiClient } from './api/client';
import { WorkspaceJob, JobDetail, IncidentCorrelationData } from './types';

export const App: React.FC = () => {
  const cachedJobsRef = useRef<Record<string, JobDetail>>({});
  const cachedCorrelationRef = useRef<IncidentCorrelationData | null>(null);

  const [currentView, setCurrentView] = useState<ViewTab>(() => {
    try {
      const p = new URLSearchParams(window.location.search).get('view');
      if (p === 'settings' || p === 'how-it-works' || p === 'supported-formats' || p === 'sanitizer') {
        return p as ViewTab;
      }
    } catch {}
    return 'sanitizer';
  });

  const [activeTab, setActiveTab] = useState<string | null>(() => {
    try {
      const p = new URLSearchParams(window.location.search);
      const jobsParam = p.get('jobs') || p.get('job_ids');
      if (p.get('tab') === 'relationship_mapping' || (jobsParam && jobsParam.includes(','))) {
        return 'relationship_mapping';
      }
      return p.get('job_id') || p.get('job') || null;
    } catch {
      return null;
    }
  });

  const [workspaceJobs, setWorkspaceJobs] = useState<WorkspaceJob[]>(() => {
    try {
      const p = new URLSearchParams(window.location.search);
      const jobsParam = p.get('jobs') || p.get('job_ids');
      if (jobsParam) {
        const ids = jobsParam.split(',').map(s => s.trim()).filter(Boolean);
        if (ids.length > 0) {
          return ids.map((id) => ({
            jobId: id,
            filename: `Job_${id.slice(0, 8)}`,
            category: 'unknown',
            riskLevel: 'ANALYZING',
          }));
        }
      }
      const initialId = p.get('job_id') || p.get('job');
      if (initialId) {
        return [{ jobId: initialId, filename: 'Artifact', category: 'unknown', riskLevel: 'ANALYZING' }];
      }
    } catch {}
    return [];
  });

  const [isUploading, setIsUploading] = useState(false);
  const [isDisclaimerOpen, setIsDisclaimerOpen] = useState(false);
  const [isDraggingOverWindow, setIsDraggingOverWindow] = useState(false);
  const [draggedCount, setDraggedCount] = useState<number>(1);
  const dragCounterRef = useRef(0);

  const [uploadProgress, setUploadProgress] = useState<{ loaded: number; total: number; percentage: number } | null>(null);
  const [uploadingFiles, setUploadingFiles] = useState<File[]>([]);
  const [duplicateNotice, setDuplicateNotice] = useState<{ message: string; type: 'warning' | 'info' } | null>(null);

  useEffect(() => {
    if (duplicateNotice) {
      const timer = setTimeout(() => {
        setDuplicateNotice(null);
      }, 7000);
      return () => clearTimeout(timer);
    }
  }, [duplicateNotice]);

  const handleUpload = async (files: File[], options?: { clearExisting?: boolean }) => {
    if (!files || files.length === 0) return;
    // Guarantee that drag overlay is dismissed immediately
    dragCounterRef.current = 0;
    setIsDraggingOverWindow(false);

    if (options?.clearExisting) {
      cachedJobsRef.current = {};
      cachedCorrelationRef.current = null;
      setWorkspaceJobs([]);
      setActiveTab(null);
      setCurrentView('sanitizer');
    }

    // 1. Deduplicate files within incoming batch
    const uniqueIncomingFiles: File[] = [];
    const seenBatchKeys = new Set<string>();
    for (const f of files) {
      const key = `${f.name}:${f.size}`;
      if (!seenBatchKeys.has(key)) {
        seenBatchKeys.add(key);
        uniqueIncomingFiles.push(f);
      }
    }

    // 2. If appending (not clearing existing), filter out files already active in workspace
    let filesToUpload = uniqueIncomingFiles;
    if (!options?.clearExisting && workspaceJobs.length > 0) {
      const duplicateFiles: File[] = [];
      const nonDuplicateFiles: File[] = [];

      for (const f of uniqueIncomingFiles) {
        const isAlreadyActive = workspaceJobs.some(j => {
          if (j.filename.toLowerCase() === f.name.toLowerCase()) {
            if (j.fileSize !== undefined && f.size > 0) {
              return j.fileSize === f.size;
            }
            return true;
          }
          const cached = cachedJobsRef.current[j.jobId];
          if (cached) {
            const matchName = (cached.original_filename || cached.filename || '').toLowerCase() === f.name.toLowerCase();
            const matchSize = !cached.file_size || !f.size || cached.file_size === f.size;
            if (matchName && matchSize) return true;
          }
          return false;
        });

        if (isAlreadyActive) {
          duplicateFiles.push(f);
        } else {
          nonDuplicateFiles.push(f);
        }
      }

      if (duplicateFiles.length > 0) {
        const dupNames = duplicateFiles.map(d => `"${d.name}"`).join(', ');
        if (nonDuplicateFiles.length === 0) {
          // All dropped files are already analyzed and active in current investigation
          const matchingJob = workspaceJobs.find(j =>
            duplicateFiles.some(d => d.name.toLowerCase() === j.filename.toLowerCase())
          );
          if (matchingJob) {
            setActiveTab(matchingJob.jobId);
            setCurrentView('sanitizer');
          }
          setDuplicateNotice({
            message: `${dupNames} is already analyzed and active in the current investigation. Duplicate upload prevented.`,
            type: 'warning'
          });
          return;
        } else {
          // Some files are new, some are duplicates
          filesToUpload = nonDuplicateFiles;
          setDuplicateNotice({
            message: `${dupNames} was already analyzed and active in the investigation (skipped). Adding remaining ${nonDuplicateFiles.length} file(s).`,
            type: 'info'
          });
        }
      }
    }

    setUploadingFiles(filesToUpload);
    setIsUploading(true);
    const totalBytes = filesToUpload.reduce((acc, f) => acc + f.size, 0);
    setUploadProgress({ loaded: 0, total: totalBytes, percentage: 0 });

    try {
      const res = await apiClient.uploadFiles(filesToUpload, (loaded, total) => {
        const percentage = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 0;
        setUploadProgress({ loaded, total, percentage });
      });
      if (res.jobs && res.jobs.length > 0) {
        const newJobs: WorkspaceJob[] = res.jobs.map(j => ({
          jobId: j.job_id,
          filename: j.filename,
          fileSize: j.file_size,
          category: 'unknown',
          riskLevel: 'ANALYZING',
        }));

        setWorkspaceJobs(prev => {
          if (options?.clearExisting) {
            return newJobs;
          }
          const existingIds = new Set(prev.map(p => p.jobId));
          const filteredNew = newJobs.filter(n => !existingIds.has(n.jobId));
          return [...prev, ...filteredNew];
        });

        setActiveTab(res.jobs[0].job_id);
        setCurrentView('sanitizer');
      } else {
        alert('Server did not return a valid job.');
      }
    } catch (err: any) {
      alert(err.message || 'File upload failed');
    } finally {
      setIsUploading(false);
      setUploadProgress(null);
      setUploadingFiles([]);
      dragCounterRef.current = 0;
      setIsDraggingOverWindow(false);
    }
  };

  const handleJobUpdate = (fullJob: JobDetail) => {
    cachedJobsRef.current[fullJob.job_id] = fullJob;
    setWorkspaceJobs(prev => prev.map(j => {
      if (j.jobId === fullJob.job_id) {
        return {
          ...j,
          filename: fullJob.original_filename || fullJob.filename || j.filename,
          category: fullJob.category || j.category,
          riskLevel: fullJob.risk?.level || j.riskLevel,
          riskScore: fullJob.risk?.score,
          fileSize: fullJob.file_size || j.fileSize,
        };
      }
      return j;
    }));
  };

  // Hydrate initial jobs if loaded with URL query parameters
  useEffect(() => {
    if (workspaceJobs.length === 0) return;
    workspaceJobs.forEach(async (j) => {
      try {
        const fullJob = await apiClient.getJobStatus(j.jobId);
        if (fullJob) {
          handleJobUpdate(fullJob);
        }
      } catch (err) {
        console.error('Failed to hydrate initial job:', j.jobId, err);
      }
    });
  }, []);

  const handleCloseJob = (jobId: string) => {
    delete cachedJobsRef.current[jobId];
    cachedCorrelationRef.current = null;
    setWorkspaceJobs(prev => {
      const next = prev.filter(j => j.jobId !== jobId);
      if (activeTab === jobId) {
        if (next.length > 0) {
          setActiveTab(next[0].jobId);
        } else {
          setActiveTab(null);
        }
      } else if (activeTab === 'relationship_mapping' && next.length < 2) {
        if (next.length > 0) {
          setActiveTab(next[0].jobId);
        } else {
          setActiveTab(null);
        }
      }
      return next;
    });
  };

  const handleClearWorkspace = () => {
    cachedJobsRef.current = {};
    cachedCorrelationRef.current = null;
    setWorkspaceJobs([]);
    setActiveTab(null);
    setCurrentView('sanitizer');
  };

  // Helper to extract file count from DataTransfer
  const extractDraggedFileCount = (dt: DataTransfer | null): number => {
    if (!dt) return 1;
    if (dt.items && dt.items.length > 0) {
      let fileItems = 0;
      for (let i = 0; i < dt.items.length; i++) {
        if (dt.items[i].kind === 'file') {
          fileItems++;
        }
      }
      return fileItems > 0 ? fileItems : dt.items.length;
    }
    if (dt.files && dt.files.length > 0) {
      return dt.files.length;
    }
    return 1;
  };

  // Global window drag-and-drop listener across all pages
  useEffect(() => {
    const handleDragEnter = (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounterRef.current += 1;
      if (e.dataTransfer && e.dataTransfer.types && Array.from(e.dataTransfer.types).includes('Files')) {
        const count = extractDraggedFileCount(e.dataTransfer);
        setDraggedCount(count);
        setIsDraggingOverWindow(true);
      }
    };

    const handleDragOver = (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer) {
        e.dataTransfer.dropEffect = 'copy';
        const count = extractDraggedFileCount(e.dataTransfer);
        if (count > 0) {
          setDraggedCount(count);
        }
      }
    };

    const handleDragLeave = (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounterRef.current -= 1;
      const isLeaving =
        e.clientX <= 0 ||
        e.clientY <= 0 ||
        e.clientX >= window.innerWidth ||
        e.clientY >= window.innerHeight ||
        !e.relatedTarget;

      if (dragCounterRef.current <= 0 && isLeaving) {
        dragCounterRef.current = 0;
        setIsDraggingOverWindow(false);
      }
    };

    const handleDrop = (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      dragCounterRef.current = 0;
      setIsDraggingOverWindow(false);

      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const droppedFiles = Array.from(e.dataTransfer.files);
        handleUpload(droppedFiles, { clearExisting: false });
      }
    };

    const handleDragEnd = () => {
      dragCounterRef.current = 0;
      setIsDraggingOverWindow(false);
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        dragCounterRef.current = 0;
        setIsDraggingOverWindow(false);
      }
    };

    window.addEventListener('dragenter', handleDragEnter);
    window.addEventListener('dragover', handleDragOver);
    window.addEventListener('dragleave', handleDragLeave);
    window.addEventListener('drop', handleDrop);
    window.addEventListener('dragend', handleDragEnd);
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      window.removeEventListener('dragenter', handleDragEnter);
      window.removeEventListener('dragover', handleDragOver);
      window.removeEventListener('dragleave', handleDragLeave);
      window.removeEventListener('drop', handleDrop);
      window.removeEventListener('dragend', handleDragEnd);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const handleUrlFetchSuccess = (jobId: string) => {
    const newJob: WorkspaceJob = {
      jobId,
      filename: 'URL Target',
      category: 'domain',
      riskLevel: 'ANALYZING',
    };
    setWorkspaceJobs(prev => {
      if (prev.some(j => j.jobId === jobId)) return prev;
      return [...prev, newJob];
    });
    setActiveTab(jobId);
    setCurrentView('sanitizer');
  };

  const handleReset = () => {
    handleClearWorkspace();
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

      {/* Duplicate Prevention Notification Toast */}
      {duplicateNotice && (
        <div className="fixed top-20 right-6 z-50 max-w-md animate-in fade-in slide-in-from-top-4 duration-300">
          <div className={`p-4 rounded-2xl shadow-xl border flex items-start gap-3 ${
            duplicateNotice.type === 'warning'
              ? 'bg-amber-50/95 border-amber-200 text-amber-900 backdrop-blur-sm'
              : 'bg-indigo-50/95 border-indigo-200 text-indigo-900 backdrop-blur-sm'
          }`}>
            <div className={`p-1.5 rounded-xl shrink-0 ${
              duplicateNotice.type === 'warning' ? 'bg-amber-100 text-amber-700' : 'bg-indigo-100 text-indigo-700'
            }`}>
              {duplicateNotice.type === 'warning' ? <AlertTriangle className="w-5 h-5" /> : <Info className="w-5 h-5" />}
            </div>
            <div className="flex-1 text-xs">
              <strong className="block font-bold mb-0.5">
                {duplicateNotice.type === 'warning' ? 'Duplicate File Detected' : 'Duplicate Files Skipped'}
              </strong>
              <p className="leading-relaxed">{duplicateNotice.message}</p>
            </div>
            <button
              onClick={() => setDuplicateNotice(null)}
              className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200/50 transition-colors cursor-pointer"
            >
              ×
            </button>
          </div>
        </div>
      )}

      <main className="flex-1 flex flex-col">
        {currentView === 'sanitizer' && workspaceJobs.length > 0 && (
          <WorkspaceTabBar
            jobs={workspaceJobs}
            activeTab={activeTab || (workspaceJobs[0]?.jobId ?? '')}
            onSelectTab={(tabId) => setActiveTab(tabId)}
            onCloseJob={handleCloseJob}
            onAddFiles={handleUpload}
            onClearWorkspace={handleClearWorkspace}
            isUploading={isUploading}
          />
        )}

        <div className="flex-1">
          {currentView === 'settings' ? (
            <div className="max-w-[96rem] mx-auto px-4 py-8">
              <SettingsView onBack={() => setCurrentView('sanitizer')} />
            </div>
          ) : currentView === 'how-it-works' ? (
            <HowItWorks 
              onGoToSanitizer={() => setCurrentView('sanitizer')}
              onGoToFormats={() => setCurrentView('supported-formats')}
            />
          ) : currentView === 'supported-formats' ? (
            <SupportedFormats 
              onGoToSanitizer={() => setCurrentView('sanitizer')}
            />
          ) : workspaceJobs.length > 0 && activeTab === 'relationship_mapping' ? (
            <ErrorBoundary fallbackTitle="Relationship Mapping Error" onReset={handleReset}>
              <RelationshipMappingView
                jobs={workspaceJobs}
                cachedData={cachedCorrelationRef.current}
                onDataLoaded={(d) => {
                  cachedCorrelationRef.current = d;
                }}
                onSelectJob={(newJobId) => setActiveTab(newJobId)}
              />
            </ErrorBoundary>
          ) : workspaceJobs.length > 0 && activeTab ? (
            <ErrorBoundary fallbackTitle="Analysis Dashboard Error" onReset={handleReset}>
              <AnalysisDashboard
                key={activeTab}
                jobId={activeTab}
                cachedJob={cachedJobsRef.current[activeTab]}
                onBack={handleReset}
                onSelectJob={(newJobId) => setActiveTab(newJobId)}
                onJobUpdate={handleJobUpdate}
                workspaceJobs={workspaceJobs}
              />
            </ErrorBoundary>
          ) : (
            <FileUpload
              onUpload={handleUpload}
              onUrlFetchSuccess={handleUrlFetchSuccess}
              isUploading={isUploading}
              uploadProgress={uploadProgress}
            />
          )}
        </div>
      </main>

      <footer className="border-t border-slate-200 bg-white py-6">
        <div className="max-w-[96rem] mx-auto px-4 text-center text-xs text-slate-500 space-y-1 font-mono">
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

      {/* Global Drag-and-Drop Ingestion Overlay with Dual-Zone Single File / Multi-File Ingestion */}
      <DragDropOverlay
        isOpen={isDraggingOverWindow}
        draggedCount={draggedCount}
        existingJobsCount={workspaceJobs.length}
        onClose={() => {
          dragCounterRef.current = 0;
          setIsDraggingOverWindow(false);
        }}
        onDropFiles={(files, mode) => {
          dragCounterRef.current = 0;
          setIsDraggingOverWindow(false);
          handleUpload(files, { clearExisting: mode === 'clear' });
        }}
      />

      {/* Global Upload Progression Graphic Modal */}
      {isUploading && (
        <UploadProgressModal
          files={uploadingFiles}
          progress={uploadProgress}
        />
      )}
    </div>
  );
};

export default App;
