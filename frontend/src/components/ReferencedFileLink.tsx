import React from 'react';
import { ExternalLink, FileCode, ArrowRight } from 'lucide-react';
import { WorkspaceJob } from '../types';
import { tokenizeReferencedText } from '../utils/crossFileReferences';

interface ReferencedFileLinkProps {
  targetJobId: string;
  targetFilename: string;
  label?: string;
  detail?: string;
  badgeOnly?: boolean;
  onSelectJob?: (jobId: string) => void;
  className?: string;
}

export const ReferencedFileLink: React.FC<ReferencedFileLinkProps> = ({
  targetJobId,
  targetFilename,
  label,
  detail,
  badgeOnly = false,
  onSelectJob,
  className = '',
}) => {
  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onSelectJob) {
      onSelectJob(targetJobId);
    }
  };

  if (badgeOnly) {
    return (
      <button
        onClick={handleClick}
        title={detail || `Navigate to ${targetFilename}`}
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold font-mono bg-indigo-50 hover:bg-indigo-100 text-indigo-700 hover:text-indigo-900 border border-indigo-200 transition-all cursor-pointer shadow-2xs ${className}`}
      >
        <span>{targetFilename}</span>
        <ExternalLink className="w-2.5 h-2.5 opacity-70" />
      </button>
    );
  }

  return (
    <button
      onClick={handleClick}
      title={detail || `Navigate to ${targetFilename}`}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white transition-all cursor-pointer shadow-xs group ${className}`}
    >
      <FileCode className="w-3.5 h-3.5 opacity-80" />
      <span className="truncate max-w-[200px]">{label ? `${label}: ${targetFilename}` : targetFilename}</span>
      <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
    </button>
  );
};

interface ReferencedTextProps {
  text?: string;
  jobs?: WorkspaceJob[];
  workspaceJobs?: WorkspaceJob[];
  currentJobId?: string;
  onSelectJob?: (jobId: string) => void;
  className?: string;
}

/**
 * Parses raw text (command lines, process names, descriptions, strings)
 * and turns any occurrences of other analyzed files into clickable interactive links.
 */
export const ReferencedText: React.FC<ReferencedTextProps> = ({
  text = '',
  jobs,
  workspaceJobs,
  currentJobId,
  onSelectJob,
  className = '',
}) => {
  const activeJobs = workspaceJobs || jobs || [];
  if (!text || activeJobs.length <= 1) {
    return <span className={className}>{text}</span>;
  }

  const tokens = tokenizeReferencedText(text, activeJobs, currentJobId);

  return (
    <span className={className}>
      {tokens.map((token, idx) => {
        if (!token.isMatch || !token.job) {
          return <span key={idx}>{token.text}</span>;
        }

        return (
          <button
            key={idx}
            onClick={(e) => {
              e.stopPropagation();
              if (onSelectJob && token.job) {
                onSelectJob(token.job.jobId);
              }
            }}
            title={`Referenced artifact: ${token.job.filename} (Click to open analysis)`}
            className="inline-flex items-center gap-0.5 mx-0.5 px-1.5 py-0.2 rounded bg-indigo-100 hover:bg-indigo-200 text-indigo-800 hover:text-indigo-950 font-bold font-mono text-[11px] border border-indigo-300 transition-colors cursor-pointer underline decoration-indigo-400 underline-offset-2"
          >
            <span>{token.text}</span>
            <ExternalLink className="w-2.5 h-2.5 opacity-70" />
          </button>
        );
      })}
    </span>
  );
};
