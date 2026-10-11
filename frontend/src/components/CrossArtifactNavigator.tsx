import React from 'react';
import { Network, ExternalLink, ArrowRight, FileCode, Paperclip, Activity, Terminal } from 'lucide-react';
import { ClientCrossReference } from '../utils/crossFileReferences';

interface CrossArtifactNavigatorProps {
  references: ClientCrossReference[];
  currentFilename?: string;
  onSelectJob?: (jobId: string) => void;
}

export const CrossArtifactNavigator: React.FC<CrossArtifactNavigatorProps> = ({
  references,
  currentFilename,
  onSelectJob,
}) => {
  if (!references || references.length === 0) return null;

  const getReferenceIcon = (type: string) => {
    if (type.includes('EMAIL')) return <Paperclip className="w-3.5 h-3.5 text-blue-600" />;
    if (type.includes('CARVED') || type.includes('NETWORK')) return <Activity className="w-3.5 h-3.5 text-emerald-600" />;
    if (type.includes('EVTX') || type.includes('PROCESS') || type.includes('SERVICE')) return <Terminal className="w-3.5 h-3.5 text-amber-600" />;
    return <FileCode className="w-3.5 h-3.5 text-indigo-600" />;
  };

  return (
    <div className="bg-gradient-to-r from-indigo-50/90 via-slate-50 to-purple-50/90 border border-indigo-200/80 rounded-2xl p-4 shadow-sm mb-6 animate-in fade-in duration-300">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-xl bg-indigo-600 text-white shadow-xs">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-900 flex items-center gap-2">
              <span>Cross-Artifact Investigation Correlation</span>
              <span className="px-2 py-0.2 bg-indigo-100 text-indigo-800 rounded-full text-[10px] font-bold">
                {references.length} Linked Reference{references.length > 1 ? 's' : ''}
              </span>
            </h4>
            <p className="text-xs text-slate-500 font-sans">
              This artifact {currentFilename ? <span className="font-semibold text-slate-700">({currentFilename})</span> : ''} shares verified cryptographic hashes, execution telemetry, carved payloads, or embedded references with other files in this investigation.
            </p>
          </div>
        </div>

        <button
          onClick={() => onSelectJob && onSelectJob('relationship_mapping')}
          className="self-start md:self-auto px-3 py-1.5 rounded-xl bg-white hover:bg-slate-50 text-indigo-700 hover:text-indigo-900 border border-indigo-200 text-xs font-semibold inline-flex items-center gap-1.5 transition-all shadow-2xs hover:shadow-xs cursor-pointer shrink-0"
        >
          <Network className="w-3.5 h-3.5" />
          <span>View in Threat Graph & Swimlanes</span>
          <ArrowRight className="w-3 h-3 opacity-70" />
        </button>
      </div>

      {/* Grid / Badges of Referenced Artifacts */}
      <div className="flex flex-wrap gap-2 pt-1">
        {references.map((ref, idx) => (
          <button
            key={idx}
            onClick={() => onSelectJob && onSelectJob(ref.targetJobId)}
            title={ref.detail}
            className="group flex items-center gap-2 px-3 py-2 rounded-xl bg-white hover:bg-indigo-50/70 border border-slate-200 hover:border-indigo-300 text-left transition-all shadow-2xs hover:shadow-sm cursor-pointer"
          >
            <div className="p-1 rounded-lg bg-slate-100 group-hover:bg-indigo-100 transition-colors">
              {getReferenceIcon(ref.referenceType)}
            </div>
            <div className="min-w-0 pr-1">
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-xs text-slate-900 group-hover:text-indigo-900 truncate max-w-[220px]">
                  {ref.targetFilename}
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 group-hover:bg-indigo-100 text-slate-600 group-hover:text-indigo-700 font-medium shrink-0">
                  {ref.label}
                </span>
              </div>
              <p className="text-[10px] text-slate-400 group-hover:text-slate-600 truncate max-w-[280px]">
                {ref.detail}
              </p>
            </div>
            <ExternalLink className="w-3 h-3 text-slate-400 group-hover:text-indigo-600 group-hover:translate-x-0.5 transition-all shrink-0 ml-auto" />
          </button>
        ))}
      </div>
    </div>
  );
};
