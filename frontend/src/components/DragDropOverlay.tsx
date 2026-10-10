import React, { useState, useRef } from 'react';
import { 
  RotateCcw, 
  PlusCircle, 
  Layers, 
  Sparkles, 
  X, 
  Files, 
  FileText, 
  ArrowRight,
  Trash2,
  CheckCircle2
} from 'lucide-react';

export interface DragDropOverlayProps {
  isOpen: boolean;
  draggedCount: number;
  existingJobsCount: number;
  onClose: () => void;
  onDropFiles: (files: File[], mode: 'clear' | 'append') => void;
}

export const DragDropOverlay: React.FC<DragDropOverlayProps> = ({
  isOpen,
  draggedCount,
  existingJobsCount,
  onClose,
  onDropFiles
}) => {
  const [hoveredZone, setHoveredZone] = useState<'clear' | 'append' | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  if (!isOpen) return null;

  const isMulti = draggedCount > 1;

  // Container dragover to smoothly highlight the hovered side
  const handleContainerDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer) {
      e.dataTransfer.dropEffect = 'copy';
    }
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      setHoveredZone(e.clientX < midX ? 'clear' : 'append');
    }
  };

  const handleContainerDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const files = Array.from(e.dataTransfer?.files || []);
    if (files.length === 0) {
      onClose();
      return;
    }

    // Determine target mode from active hover or drop coordinates
    let targetMode: 'clear' | 'append' = hoveredZone || 'append';
    if (!hoveredZone && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      targetMode = e.clientX < rect.left + rect.width / 2 ? 'clear' : 'append';
    }

    onDropFiles(files, targetMode);
  };

  return (
    <div 
      className="fixed inset-0 z-[99999] bg-slate-900/50 backdrop-blur-md flex items-center justify-center p-4 sm:p-6 animate-fade-in select-none"
      onClick={onClose}
      onDragOver={(e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer) {
          e.dataTransfer.dropEffect = 'copy';
        }
      }}
      onDragLeave={(e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.clientX <= 0 || e.clientY <= 0 || e.clientX >= window.innerWidth || e.clientY >= window.innerHeight) {
          onClose();
        }
      }}
      onDrop={(e) => {
        e.preventDefault();
        e.stopPropagation();
        const files = Array.from(e.dataTransfer?.files || []);
        if (files.length > 0) {
          const isLeft = e.clientX < window.innerWidth / 2;
          onDropFiles(files, isLeft ? 'clear' : 'append');
        } else {
          onClose();
        }
      }}
    >
      <div 
        ref={containerRef}
        onClick={(e) => e.stopPropagation()}
        onDragOver={handleContainerDragOver}
        onDrop={handleContainerDrop}
        className="bg-white rounded-3xl border border-slate-200/90 shadow-2xl p-6 sm:p-8 max-w-4xl w-full relative overflow-hidden animate-modal-fade cursor-default"
      >
        {/* Top Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-full transition-colors cursor-pointer z-20"
          title="Cancel & Close"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Ambient Background Glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[500px] h-48 bg-gradient-to-b from-indigo-500/10 to-transparent rounded-full blur-3xl pointer-events-none" />

        {/* Modal Header */}
        <div className="text-center max-w-xl mx-auto mb-6 relative z-10 pointer-events-none">
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200/80 mb-2">
            {isMulti ? (
              <>
                <Files className="w-3.5 h-3.5 text-indigo-600" />
                Multi-File Ingestion ({draggedCount} Files Detected)
              </>
            ) : (
              <>
                <FileText className="w-3.5 h-3.5 text-indigo-600" />
                Single Artifact Ingestion
              </>
            )}
          </span>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
            {isMulti 
              ? `Choose Analysis Target Zone for ${draggedCount} Files`
              : 'Choose Analysis Target Zone'
            }
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            {isMulti
              ? `Drop files onto the left area to clear previous session and analyze all ${draggedCount} files fresh, or onto the right area to append to your active investigation.`
              : 'Drop file onto the left area to start a fresh clean session, or onto the right area to append to your active investigation.'
            }
          </p>
        </div>

        {/* Dual Target Drop Zones */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 relative z-10">
          {/* ============================================================== */}
          {/* LEFT TARGET AREA: CLEAR PREVIOUS & START FRESH                 */}
          {/* ============================================================== */}
          <div
            id="drop-zone-clear"
            onDragEnter={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setHoveredZone('clear');
            }}
            onDragOver={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setHoveredZone('clear');
              if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
            }}
            onDragLeave={(e) => {
              e.preventDefault();
              e.stopPropagation();
            }}
            onDrop={(e) => {
              e.preventDefault();
              e.stopPropagation();
              const files = Array.from(e.dataTransfer?.files || []);
              if (files.length > 0) {
                onDropFiles(files, 'clear');
              } else {
                onClose();
              }
            }}
            className={`relative rounded-2xl p-6 transition-all duration-200 cursor-pointer flex flex-col justify-between text-left ${
              hoveredZone === 'clear'
                ? 'border-2 border-amber-500 ring-4 ring-amber-300/40 shadow-[0_0_30px_rgba(245,158,11,0.28)] bg-gradient-to-b from-amber-50/90 via-amber-50/40 to-white scale-[1.015]'
                : hoveredZone === 'append'
                ? 'border-2 border-dashed border-slate-200/90 bg-slate-50/40 opacity-60 scale-[0.99]'
                : 'border-2 border-dashed border-amber-300/80 bg-gradient-to-b from-amber-50/30 to-white hover:border-amber-400 hover:bg-amber-50/50'
            }`}
          >
            {/* Header Badges */}
            <div className="flex items-center justify-between gap-2 mb-4 pointer-events-none">
              <span className="px-2.5 py-1 rounded-full text-[11px] font-bold uppercase tracking-wider bg-amber-100 text-amber-900 border border-amber-300/80 flex items-center gap-1.5 shadow-xs">
                <RotateCcw className="w-3 h-3 text-amber-700" />
                Clear & Replace
              </span>
              {existingJobsCount > 0 ? (
                <span className="px-2 py-0.5 rounded-md text-[10px] font-medium font-mono bg-amber-50 text-amber-800 border border-amber-200">
                  Will clear {existingJobsCount} file{existingJobsCount > 1 ? 's' : ''}
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-md text-[10px] font-medium font-mono bg-slate-100 text-slate-600 border border-slate-200">
                  Workspace empty
                </span>
              )}
            </div>

            {/* Center Visual & Title */}
            <div className="pointer-events-none mb-5">
              <div className="flex items-center gap-3 mb-2.5">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center transition-all duration-200 ${
                  hoveredZone === 'clear'
                    ? 'bg-amber-500 text-white shadow-md shadow-amber-500/30'
                    : 'bg-amber-100 text-amber-700'
                }`}>
                  <RotateCcw className={`w-6 h-6 ${hoveredZone === 'clear' ? 'animate-spin' : ''}`} style={{ animationDuration: '6s' }} />
                </div>
                <div>
                  <h3 className="text-base sm:text-lg font-bold text-slate-900 leading-snug">
                    Clear Previous & Start Fresh
                  </h3>
                  <p className="text-[11px] font-mono text-amber-800 font-medium">
                    {isMulti 
                      ? `Reset analysis area • Fresh batch analysis (${draggedCount} files)`
                      : 'Reset analysis area • Isolated session'
                    }
                  </p>
                </div>
              </div>

              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                {isMulti
                  ? `Wipes all previously analyzed files from the workspace and launches fresh multi-item analysis for all ${draggedCount} files.`
                  : 'Wipes all previously analyzed files from the workspace and starts a brand new, isolated analysis for this file.'
                }
              </p>

              {/* Sub-bullets */}
              <div className="space-y-1.5 text-[11px] text-slate-600 font-mono bg-white/80 p-3 rounded-xl border border-amber-200/70">
                <div className="flex items-center gap-1.5">
                  <Trash2 className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  <span>Purges previous file tabs & correlation cache</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  <span>
                    {isMulti 
                      ? `Initializes new multi-artifact incident workspace`
                      : 'Focuses on this single file exclusively'
                    }
                  </span>
                </div>
              </div>
            </div>

            {/* Action Drop Button / Pill */}
            <div className={`w-full py-2.5 px-4 rounded-xl font-bold text-xs flex items-center justify-center gap-2 transition-all duration-200 pointer-events-none ${
              hoveredZone === 'clear'
                ? 'bg-amber-600 text-white shadow-lg shadow-amber-600/30'
                : 'bg-amber-100/80 text-amber-900 border border-amber-300/80'
            }`}>
              <span>
                {isMulti 
                  ? `Drop Here to Clear & Analyze ${draggedCount} Files`
                  : 'Drop Here to Clear & Analyze'
                }
              </span>
              <ArrowRight className="w-3.5 h-3.5" />
            </div>
          </div>

          {/* ============================================================== */}
          {/* RIGHT TARGET AREA: ADD TO CURRENT ANALYSIS                      */}
          {/* ============================================================== */}
          <div
            id="drop-zone-append"
            onDragEnter={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setHoveredZone('append');
            }}
            onDragOver={(e) => {
              e.preventDefault();
              e.stopPropagation();
              setHoveredZone('append');
              if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
            }}
            onDragLeave={(e) => {
              e.preventDefault();
              e.stopPropagation();
            }}
            onDrop={(e) => {
              e.preventDefault();
              e.stopPropagation();
              const files = Array.from(e.dataTransfer?.files || []);
              if (files.length > 0) {
                onDropFiles(files, 'append');
              } else {
                onClose();
              }
            }}
            className={`relative rounded-2xl p-6 transition-all duration-200 cursor-pointer flex flex-col justify-between text-left ${
              hoveredZone === 'append'
                ? 'border-2 border-indigo-500 ring-4 ring-indigo-300/40 shadow-[0_0_30px_rgba(99,102,241,0.28)] bg-gradient-to-b from-indigo-50/90 via-indigo-50/40 to-white scale-[1.015]'
                : hoveredZone === 'clear'
                ? 'border-2 border-dashed border-slate-200/90 bg-slate-50/40 opacity-60 scale-[0.99]'
                : 'border-2 border-dashed border-indigo-300/80 bg-gradient-to-b from-indigo-50/30 to-white hover:border-indigo-400 hover:bg-indigo-50/50'
            }`}
          >
            {/* Header Badges */}
            <div className="flex items-center justify-between gap-2 mb-4 pointer-events-none">
              <span className="px-2.5 py-1 rounded-full text-[11px] font-bold uppercase tracking-wider bg-indigo-100 text-indigo-900 border border-indigo-300/80 flex items-center gap-1.5 shadow-xs">
                <PlusCircle className="w-3 h-3 text-indigo-700" />
                Keep & Append
              </span>
              {existingJobsCount > 0 ? (
                <span className="px-2 py-0.5 rounded-md text-[10px] font-medium font-mono bg-indigo-50 text-indigo-800 border border-indigo-200">
                  {isMulti 
                    ? `Adds ${draggedCount} to ${existingJobsCount} active file${existingJobsCount > 1 ? 's' : ''}`
                    : `Appends to ${existingJobsCount} active file${existingJobsCount > 1 ? 's' : ''}`
                  }
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-md text-[10px] font-medium font-mono bg-emerald-50 text-emerald-800 border border-emerald-200">
                  Starts workspace
                </span>
              )}
            </div>

            {/* Center Visual & Title */}
            <div className="pointer-events-none mb-5">
              <div className="flex items-center gap-3 mb-2.5">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center transition-all duration-200 ${
                  hoveredZone === 'append'
                    ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                    : 'bg-indigo-100 text-indigo-700'
                }`}>
                  <Layers className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base sm:text-lg font-bold text-slate-900 leading-snug">
                    Add to Current Analysis
                  </h3>
                  <p className="text-[11px] font-mono text-indigo-800 font-medium">
                    {isMulti
                      ? `Preserve active files • Add ${draggedCount} files to investigation`
                      : 'Preserve active files • Multi-artifact correlation'
                    }
                  </p>
                </div>
              </div>

              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                {isMulti
                  ? `Keeps all currently analyzed files and appends all ${draggedCount} files to your active incident investigation workspace.`
                  : 'Keeps all currently analyzed files and adds this file to your active incident investigation workspace.'
                }
              </p>

              {/* Sub-bullets */}
              <div className="space-y-1.5 text-[11px] text-slate-600 font-mono bg-white/80 p-3 rounded-xl border border-indigo-200/70">
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                  <span>Preserves all active file tabs & decompiler renames</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                  <span>Enables BinDiff, Threat Graph & Kill Chain</span>
                </div>
              </div>
            </div>

            {/* Action Drop Button / Pill */}
            <div className={`w-full py-2.5 px-4 rounded-xl font-bold text-xs flex items-center justify-center gap-2 transition-all duration-200 pointer-events-none ${
              hoveredZone === 'append'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
                : 'bg-indigo-100/80 text-indigo-900 border border-indigo-300/80'
            }`}>
              <span>
                {isMulti 
                  ? `Drop Here to Append ${draggedCount} Files`
                  : 'Drop Here to Append File'
                }
              </span>
              <ArrowRight className="w-3.5 h-3.5" />
            </div>
          </div>
        </div>

        {/* Footer Info */}
        <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center justify-between text-[11px] text-slate-400 font-mono pointer-events-none">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Hover over either target to inspect action • Press ESC to cancel</span>
          </span>
          <div className="flex gap-1.5">
            {['.PDF', '.DOCX', '.EXE', '.ZIP', '.EML', '.PCAP', '.EVTX'].map(ext => (
              <span key={ext} className="px-1.5 py-0.5 bg-slate-100 text-slate-500 rounded font-semibold text-[10px]">
                {ext}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
