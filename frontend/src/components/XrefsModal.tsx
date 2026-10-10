import React, { useState, useMemo } from 'react';
import {
  X,
  Search,
  ExternalLink,
  ArrowRight,
  ArrowLeft,
  Layers,
  Code2,
  Database,
  Type,
  CornerDownRight
} from 'lucide-react';
import { XrefData, XrefEntry } from '../types';
import { lookupXrefsForSymbol } from '../utils/xrefEngine';

interface XrefsModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialSymbol: string;
  xrefsData?: XrefData;
  onJumpToAddress?: (address: string) => void;
}

export const XrefsModal: React.FC<XrefsModalProps> = ({
  isOpen,
  onClose,
  initialSymbol,
  xrefsData,
  onJumpToAddress
}) => {
  const [history, setHistory] = useState<string[]>([initialSymbol]);
  const [historyIndex, setHistoryIndex] = useState<number>(0);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [activeCategory, setActiveCategory] = useState<'all' | 'calls' | 'jumps' | 'data' | 'strings'>('all');

  const currentSymbol = history[historyIndex] || initialSymbol;

  // Whenever initialSymbol changes from outside, reset history
  React.useEffect(() => {
    if (initialSymbol) {
      setHistory([initialSymbol]);
      setHistoryIndex(0);
      setSearchFilter('');
    }
  }, [initialSymbol]);

  const navigateToSymbol = (sym: string) => {
    const newHist = history.slice(0, historyIndex + 1);
    newHist.push(sym);
    setHistory(newHist);
    setHistoryIndex(newHist.length - 1);
  };

  const handleBack = () => {
    if (historyIndex > 0) {
      setHistoryIndex(historyIndex - 1);
    }
  };

  const handleForward = () => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(historyIndex + 1);
    }
  };

  // Compute all available targets
  const allAvailableTargets = useMemo(() => {
    if (!xrefsData || !xrefsData.target_to_xrefs) return [];
    return Object.entries(xrefsData.target_to_xrefs)
      .map(([target, entries]) => ({
        target,
        count: entries.length
      }))
      .sort((a, b) => b.count - a.count);
  }, [xrefsData]);

  // Compute all unique XREFs across the binary
  const globalAllEntries: XrefEntry[] = useMemo(() => {
    if (!xrefsData || !xrefsData.target_to_xrefs) return [];
    const seen = new Set<string>();
    const list: XrefEntry[] = [];
    Object.values(xrefsData.target_to_xrefs).forEach((entries) => {
      entries.forEach((e) => {
        const key = `${e.from_address}_${e.target}_${e.instruction}`;
        if (!seen.has(key)) {
          seen.add(key);
          list.push(e);
        }
      });
    });
    return list;
  }, [xrefsData]);

  const isGlobalView = !currentSymbol || currentSymbol === 'ALL' || currentSymbol === 'All References' || (currentSymbol === 'entry_point' && lookupXrefsForSymbol(xrefsData, currentSymbol).length === 0);

  const allEntries: XrefEntry[] = useMemo(() => {
    if (isGlobalView) {
      return globalAllEntries;
    }
    const specific = lookupXrefsForSymbol(xrefsData, currentSymbol);
    if (specific.length === 0) {
      return globalAllEntries;
    }
    return specific;
  }, [isGlobalView, globalAllEntries, xrefsData, currentSymbol]);

  const filteredEntries = useMemo(() => {
    return allEntries.filter((entry) => {
      // Category filter
      if (activeCategory === 'calls' && !entry.ref_type.includes('CALL')) return false;
      if (activeCategory === 'jumps' && !entry.ref_type.includes('JUMP')) return false;
      if (activeCategory === 'data' && !['DATA_READ', 'DATA_WRITE'].includes(entry.ref_type)) return false;
      if (activeCategory === 'strings' && entry.ref_type !== 'STRING_REF') return false;

      // Text search
      if (searchFilter.trim()) {
        const q = searchFilter.toLowerCase();
        return (
          entry.from_address.toLowerCase().includes(q) ||
          entry.from_function.toLowerCase().includes(q) ||
          entry.instruction.toLowerCase().includes(q) ||
          entry.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allEntries, activeCategory, searchFilter]);

  if (!isOpen) return null;

  const counts = {
    all: allEntries.length,
    calls: allEntries.filter((e) => e.ref_type.includes('CALL')).length,
    jumps: allEntries.filter((e) => e.ref_type.includes('JUMP')).length,
    data: allEntries.filter((e) => ['DATA_READ', 'DATA_WRITE'].includes(e.ref_type)).length,
    strings: allEntries.filter((e) => e.ref_type === 'STRING_REF').length,
  };

  const getBadgeStyle = (refType: string) => {
    if (refType.includes('CALL')) {
      return 'bg-blue-50 text-blue-700 border-blue-200';
    }
    if (refType.includes('JUMP')) {
      return 'bg-purple-50 text-purple-700 border-purple-200';
    }
    if (refType === 'STRING_REF') {
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
    return 'bg-amber-50 text-amber-700 border-amber-200';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
      <div className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-4xl flex flex-col max-h-[85vh] animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/70 rounded-t-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100/70 text-blue-700 rounded-lg">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold text-slate-900 text-base">Cross-References (XREFs) Explorer</h3>
                <span className="px-2 py-0.5 text-xs font-mono font-medium bg-blue-50 text-blue-800 border border-blue-200 rounded">
                  {isGlobalView ? `All References (${globalAllEntries.length})` : currentSymbol}
                </span>
              </div>
              <p className="text-xs text-slate-500">
                {isGlobalView
                  ? `Tracking all ${globalAllEntries.length} code callers, jump branches, API invocations, and string references in this binary.`
                  : `Tracking all code callers, jump branches, and data/string references pointing to ${currentSymbol}.`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* History navigation */}
            <div className="flex items-center bg-white border border-slate-200 rounded-lg p-0.5 mr-2">
              <button
                onClick={handleBack}
                disabled={historyIndex <= 0}
                className="p-1 rounded hover:bg-slate-100 disabled:opacity-30 disabled:pointer-events-none text-slate-600"
                title="Previous symbol"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
              <span className="px-1.5 text-[11px] font-mono text-slate-400">
                {historyIndex + 1}/{history.length}
              </span>
              <button
                onClick={handleForward}
                disabled={historyIndex >= history.length - 1}
                className="p-1 rounded hover:bg-slate-100 disabled:opacity-30 disabled:pointer-events-none text-slate-600"
                title="Next symbol"
              >
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Target Switcher & Hotspots Bar */}
        <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-slate-600">Target:</span>
            <button
              onClick={() => navigateToSymbol('ALL')}
              className={`px-2 py-0.5 rounded font-mono text-[11px] font-semibold border transition-colors cursor-pointer ${
                isGlobalView
                  ? 'bg-blue-600 text-white border-blue-600 shadow-2xs'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100'
              }`}
            >
              All References ({globalAllEntries.length})
            </button>
            {/* Quick dropdown / selection of targets */}
            <select
              value={isGlobalView ? 'ALL' : currentSymbol}
              onChange={(e) => navigateToSymbol(e.target.value)}
              className="bg-white border border-slate-300 rounded px-2 py-0.5 text-[11px] font-mono text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500 max-w-xs truncate cursor-pointer"
            >
              <option value="ALL">All Targets ({globalAllEntries.length} refs)</option>
              {allAvailableTargets.map((t) => (
                <option key={t.target} value={t.target}>
                  {t.target} ({t.count} refs)
                </option>
              ))}
            </select>
          </div>

          {/* Hotspots Quick Chips */}
          {xrefsData?.hotspots && xrefsData.hotspots.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[10px] text-slate-400 font-semibold uppercase">Hotspots:</span>
              {xrefsData.hotspots.slice(0, 4).map((h) => (
                <button
                  key={h.target}
                  onClick={() => navigateToSymbol(h.target)}
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono border transition-colors cursor-pointer ${
                    currentSymbol === h.target
                      ? 'bg-indigo-600 text-white border-indigo-600 font-bold'
                      : 'bg-indigo-50 text-indigo-700 border-indigo-200 hover:bg-indigo-100'
                  }`}
                  title={`${h.references_count} callers`}
                >
                  {h.target} ({h.references_count})
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Toolbar & Filters */}
        <div className="p-3 border-b border-slate-100 bg-white flex flex-wrap items-center justify-between gap-2">
          {/* Category Tabs */}
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setActiveCategory('all')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
                activeCategory === 'all'
                  ? 'bg-blue-50 text-blue-700 border border-blue-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              All <span className="text-[10px] opacity-75 font-mono">({counts.all})</span>
            </button>
            <button
              onClick={() => setActiveCategory('calls')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
                activeCategory === 'calls'
                  ? 'bg-blue-50 text-blue-700 border border-blue-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <Code2 className="w-3.5 h-3.5 text-blue-600" />
              Calls <span className="text-[10px] opacity-75 font-mono">({counts.calls})</span>
            </button>
            <button
              onClick={() => setActiveCategory('jumps')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
                activeCategory === 'jumps'
                  ? 'bg-purple-50 text-purple-700 border border-purple-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <CornerDownRight className="w-3.5 h-3.5 text-purple-600" />
              Jumps <span className="text-[10px] opacity-75 font-mono">({counts.jumps})</span>
            </button>
            <button
              onClick={() => setActiveCategory('data')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
                activeCategory === 'data'
                  ? 'bg-amber-50 text-amber-700 border border-amber-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <Database className="w-3.5 h-3.5 text-amber-600" />
              Data <span className="text-[10px] opacity-75 font-mono">({counts.data})</span>
            </button>
            <button
              onClick={() => setActiveCategory('strings')}
              className={`px-2.5 py-1 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
                activeCategory === 'strings'
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : 'text-slate-600 hover:bg-slate-100 border border-transparent'
              }`}
            >
              <Type className="w-3.5 h-3.5 text-emerald-600" />
              Strings <span className="text-[10px] opacity-75 font-mono">({counts.strings})</span>
            </button>
          </div>

          {/* Search Input */}
          <div className="relative min-w-[240px]">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Filter by caller, address, instruction..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full pl-8 pr-3 py-1 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500 focus:bg-white"
            />
          </div>
        </div>

        {/* XREF Table Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {filteredEntries.length === 0 ? (
            <div className="text-center py-12">
              <Layers className="w-10 h-10 text-slate-300 mx-auto mb-2" />
              <p className="text-sm font-medium text-slate-700">No cross-references found for "{currentSymbol}"</p>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                {allEntries.length > 0
                  ? 'Try selecting a different category filter or clearing the search term.'
                  : 'This symbol or address has no recorded incoming callers or references in this disassembly sample.'}
              </p>
              {!isGlobalView && (
                <button
                  onClick={() => navigateToSymbol('ALL')}
                  className="mt-3.5 px-3.5 py-1.5 bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg text-xs font-semibold border border-blue-200 transition-colors cursor-pointer"
                >
                  View All References ({globalAllEntries.length})
                </button>
              )}
            </div>
          ) : (
            <div className="overflow-hidden border border-slate-200 rounded-lg">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-semibold uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Address</th>
                    <th className="py-2.5 px-3">Function Context</th>
                    {isGlobalView && <th className="py-2.5 px-3">Referenced Target</th>}
                    <th className="py-2.5 px-3 font-mono">Instruction</th>
                    <th className="py-2.5 px-3">Description</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredEntries.map((entry, idx) => (
                    <tr
                      key={idx}
                      className="hover:bg-blue-50/40 transition-colors group cursor-pointer"
                      onClick={() => onJumpToAddress && onJumpToAddress(entry.from_address)}
                    >
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${getBadgeStyle(
                            entry.ref_type
                          )}`}
                        >
                          {entry.ref_type}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono text-slate-700 font-medium whitespace-nowrap">
                        {entry.from_address}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigateToSymbol(entry.from_function);
                          }}
                          className="text-blue-600 hover:text-blue-800 hover:underline font-mono text-xs text-left"
                          title="Click to inspect XREFs of this caller function"
                        >
                          {entry.from_function}
                        </button>
                      </td>
                      {isGlobalView && (
                        <td className="py-2 px-3 whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (entry.target) navigateToSymbol(entry.target);
                            }}
                            className="text-indigo-600 hover:text-indigo-800 hover:underline font-mono text-xs font-bold text-left"
                            title="Filter XREFs to this target"
                          >
                            {entry.target}
                          </button>
                        </td>
                      )}
                      <td className="py-2 px-3 font-mono text-slate-800 font-medium">
                        {entry.instruction}
                      </td>
                      <td className="py-2 px-3 text-slate-500 truncate max-w-[200px]" title={entry.description}>
                        {entry.description}
                      </td>
                      <td className="py-2 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (onJumpToAddress) onJumpToAddress(entry.from_address);
                            onClose();
                          }}
                          className="px-2 py-1 text-[11px] font-medium text-blue-600 hover:text-blue-800 hover:bg-blue-100/60 rounded flex items-center gap-1 ml-auto transition-colors"
                        >
                          Jump <ExternalLink className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500 rounded-b-xl">
          <div className="flex items-center gap-2">
            <span>
              Showing {filteredEntries.length} of {allEntries.length} reference{allEntries.length === 1 ? '' : 's'}
            </span>
            {xrefsData?.hotspots && xrefsData.hotspots.length > 0 && (
              <span className="hidden sm:inline-block text-[11px] text-slate-400">
                • {xrefsData.hotspots.length} high-frequency call dispatchers identified
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="px-3 py-1 bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-lg text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
