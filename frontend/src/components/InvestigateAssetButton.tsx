import React, { useState } from 'react';
import { Globe, Loader2, ArrowUpRight, CheckCircle2 } from 'lucide-react';
import { apiClient } from '../api/client';

interface InvestigateAssetButtonProps {
  ioc: string;
  iocType?: 'domain' | 'ip' | 'url';
  onNavigateToJob?: (jobId: string) => void;
  className?: string;
  compact?: boolean;
  label?: string;
}

export const InvestigateAssetButton: React.FC<InvestigateAssetButtonProps> = ({
  ioc,
  iocType,
  onNavigateToJob,
  className = '',
  compact = false,
  label
}) => {
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const cleanIoc = (ioc || '').trim();
  if (!cleanIoc) return null;

  const handleClick = async (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    if (loading) return;

    setLoading(true);
    setFeedback('Initiating...');

    try {
      const res = await apiClient.investigateIoc(cleanIoc, iocType);
      if (res.already_analyzed) {
        setFeedback('Existing asset found!');
      } else {
        setFeedback('Investigation started!');
      }

      setTimeout(() => {
        if (res.job_id && onNavigateToJob) {
          onNavigateToJob(res.job_id);
        }
        setFeedback(null);
        setLoading(false);
      }, 700);
    } catch (err: any) {
      setFeedback(err.message || 'Investigation error');
      setTimeout(() => {
        setFeedback(null);
        setLoading(false);
      }, 3000);
    }
  };

  if (compact) {
    return (
      <button
        onClick={handleClick}
        disabled={loading}
        title={`Investigate remote asset '${cleanIoc}'`}
        className={`inline-flex items-center gap-1 p-1 rounded-md text-xs font-medium text-blue-600 hover:text-blue-800 hover:bg-blue-50 border border-blue-200 transition-colors cursor-pointer disabled:opacity-50 ${className}`}
      >
        {loading ? (
          <Loader2 className="w-3 h-3 animate-spin" />
        ) : (
          <Globe className="w-3 h-3" />
        )}
        {feedback ? (
          <span className="text-[10px] text-blue-700 font-semibold">{feedback}</span>
        ) : (
          <ArrowUpRight className="w-2.5 h-2.5 opacity-70" />
        )}
      </button>
    );
  }

  return (
    <button
      onClick={handleClick}
      disabled={loading}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 shadow-2xs transition-all cursor-pointer disabled:opacity-50 ${className}`}
      title={`Investigate remote infrastructure for '${cleanIoc}'`}
    >
      {loading ? (
        <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-600" />
      ) : feedback ? (
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
      ) : (
        <Globe className="w-3.5 h-3.5 text-blue-600" />
      )}
      <span>{feedback || label || 'Investigate Asset'}</span>
      {!loading && !feedback && <ArrowUpRight className="w-3 h-3 opacity-60 ml-0.5" />}
    </button>
  );
};
