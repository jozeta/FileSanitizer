import React, { useRef } from 'react';
import {
  FileText,
  FileCode,
  FileSpreadsheet,
  Cpu,
  Mail,
  Activity,
  Terminal,
  Image as ImageIcon,
  FolderArchive,
  Network,
  Plus,
  X,
  Trash2,
  RefreshCw
} from 'lucide-react';
import { WorkspaceJob } from '../types';

interface WorkspaceTabBarProps {
  jobs: WorkspaceJob[];
  activeTab: string; // jobId or 'relationship_mapping'
  onSelectTab: (tabId: string) => void;
  onCloseJob: (jobId: string) => void;
  onAddFiles: (files: File[]) => void;
  onClearWorkspace: () => void;
  isUploading?: boolean;
}

function getFileIcon(category?: string, filename?: string) {
  const cat = (category || '').toLowerCase();
  const name = (filename || '').toLowerCase();

  if (cat === 'executable' || cat === 'binary' || name.match(/\.(exe|dll|sys|elf|bin|macho)$/)) {
    return Cpu;
  }
  if (cat === 'pcap' || name.match(/\.(pcap|pcapng|cap)$/)) {
    return Activity;
  }
  if (cat === 'evtx' || name.endsWith('.evtx')) {
    return Terminal;
  }
  if (cat === 'office' || name.match(/\.(docx?|xlsx?|pptx?|docm|xlsm|pptm|rtf)$/)) {
    return FileSpreadsheet;
  }
  if (cat === 'email' || name.match(/\.(eml|msg)$/)) {
    return Mail;
  }
  if (cat === 'script' || name.match(/\.(ps1|bat|vbs|sh|py|js|php)$/)) {
    return FileCode;
  }
  if (cat === 'archive' || name.match(/\.(zip|rar|7z|tar|gz)$/)) {
    return FolderArchive;
  }
  if (cat === 'image' || name.match(/\.(png|jpe?g|gif|webp|bmp|tiff?)$/)) {
    return ImageIcon;
  }
  return FileText;
}

function getRiskDotColor(level?: string) {
  const l = (level || '').toUpperCase();
  if (l.includes('MALICIOUS') || l.includes('CRITICAL')) return 'bg-rose-500 shadow-rose-500/50';
  if (l.includes('SUSPICIOUS') || l.includes('HIGH')) return 'bg-amber-500 shadow-amber-500/50';
  if (l.includes('MEDIUM') || l.includes('LOW')) return 'bg-yellow-400 shadow-yellow-400/50';
  if (l.includes('CLEAN')) return 'bg-emerald-500 shadow-emerald-500/50';
  return 'bg-blue-400 animate-pulse';
}

export const WorkspaceTabBar: React.FC<WorkspaceTabBarProps> = ({
  jobs,
  activeTab,
  onSelectTab,
  onCloseJob,
  onAddFiles,
  onClearWorkspace,
  isUploading = false,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  if (!jobs || jobs.length === 0) return null;

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onAddFiles(Array.from(e.target.files));
      e.target.value = '';
    }
  };

  const isMultiFile = jobs.length >= 2;

  return (
    <div className="bg-white border-b border-slate-200 text-slate-700 sticky top-0 z-30 shadow-xs">
      <div className="max-w-[96rem] mx-auto px-4 flex items-center justify-between gap-3 overflow-x-auto py-1.5 scrollbar-thin scrollbar-thumb-slate-300">
        
        {/* Left Side: File Tabs & Relationship Mapping Tab */}
        <div className="flex items-center gap-1.5 min-w-0 flex-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-400 px-2 select-none hidden lg:block">
            Workspace ({jobs.length})
          </div>

          {/* Individual File Tabs */}
          {jobs.map((job) => {
            const Icon = getFileIcon(job.category, job.filename);
            const isActive = activeTab === job.jobId;
            const dotColor = getRiskDotColor(job.riskLevel);

            return (
              <div
                key={job.jobId}
                onClick={() => onSelectTab(job.jobId)}
                title={job.filename}
                className={`group relative flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-all duration-150 select-none max-w-[200px] border ${
                  isActive
                    ? 'bg-white text-slate-900 border-indigo-500 shadow-xs font-semibold ring-1 ring-indigo-500/20'
                    : 'bg-slate-50/80 text-slate-600 hover:text-slate-900 hover:bg-slate-100 border-slate-200/90'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-indigo-600' : 'text-slate-400 group-hover:text-slate-600'}`} />
                
                <span className="truncate">{job.filename}</span>

                {/* Risk Dot */}
                <span className={`w-2 h-2 rounded-full shrink-0 shadow-xs ${dotColor}`} />

                {/* Close Tab Button */}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onCloseJob(job.jobId);
                  }}
                  className="opacity-0 group-hover:opacity-100 hover:bg-slate-200 p-0.5 rounded text-slate-400 hover:text-slate-700 transition-opacity ml-1"
                  title="Remove from workspace"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            );
          })}

          {/* Relationship Mapping Special Tab (when 2+ files are in workspace) */}
          {isMultiFile && (
            <button
              type="button"
              onClick={() => onSelectTab('relationship_mapping')}
              className={`relative flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-all duration-150 select-none border shrink-0 ${
                activeTab === 'relationship_mapping'
                  ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm font-semibold'
                  : 'bg-indigo-50/70 text-indigo-700 hover:bg-indigo-100/80 hover:text-indigo-900 border-indigo-200/80'
              }`}
            >
              <Network className={`w-3.5 h-3.5 ${activeTab === 'relationship_mapping' ? 'text-white' : 'text-indigo-600'}`} />
              <span>Relationship Mapping</span>
              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full border ${
                activeTab === 'relationship_mapping'
                  ? 'bg-white/20 text-white border-white/30'
                  : 'bg-indigo-100 text-indigo-700 border-indigo-200'
              }`}>
                {jobs.length} files
              </span>
            </button>
          )}
        </div>

        {/* Right Side: Add File & Clear Workspace Controls */}
        <div className="flex items-center gap-2 shrink-0">
          <input
            type="file"
            multiple
            ref={fileInputRef}
            onChange={handleFileInputChange}
            className="hidden"
          />

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={isUploading}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 shadow-xs hover:border-slate-400 transition-colors disabled:opacity-50"
            title="Add another file to this investigation"
          >
            {isUploading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-600" />
            ) : (
              <Plus className="w-3.5 h-3.5 text-indigo-600" />
            )}
            <span>Add File</span>
          </button>

          <button
            type="button"
            onClick={onClearWorkspace}
            className="p-1 rounded-md text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
            title="Clear all files from workspace"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>
    </div>
  );
};
