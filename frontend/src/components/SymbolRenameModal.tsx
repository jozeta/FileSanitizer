import React, { useState, useEffect, useMemo } from 'react';
import {
  X,
  Edit3,
  Tag,
  Code2,
  Trash2,
  RotateCcw,
  Check,
  AlertCircle,
  Hash,
  Type,
  Layers,
  ArrowRight,
  Search
} from 'lucide-react';
import { useSymbolRenames, SymbolCategory } from '../context/SymbolRenameContext';

interface SymbolRenameModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialOriginal?: string;
  initialCategory?: SymbolCategory;
  discoveredFunctions?: string[];
  discoveredVariables?: string[];
  discoveredStrings?: string[];
  sourceCode?: string;
  binaryScope?: string;
}

export const SymbolRenameModal: React.FC<SymbolRenameModalProps> = ({
  isOpen,
  onClose,
  initialOriginal = '',
  initialCategory = 'function',
  discoveredFunctions = [],
  discoveredVariables = [],
  discoveredStrings = [],
  sourceCode = '',
  binaryScope = 'all'
}) => {
  const { renames, addOrUpdateRename, removeRename, clearRenames } = useSymbolRenames();

  const [category, setCategory] = useState<SymbolCategory>(initialCategory);
  const [original, setOriginal] = useState<string>(initialOriginal);
  const [renamed, setRenamed] = useState<string>('');
  const [filterSearch, setFilterSearch] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [successMessage, setSuccessMessage] = useState<string>('');

  // Synchronize when initial props change
  useEffect(() => {
    if (isOpen) {
      if (initialOriginal) {
        setOriginal(initialOriginal);
        // If it's already renamed, set current rename as default
        const existing = renames.find(
          (r) => r.original.toLowerCase() === initialOriginal.trim().toLowerCase()
        );
        if (existing) {
          setRenamed(existing.renamed);
          setCategory(existing.category);
        } else {
          setRenamed('');
          setCategory(initialCategory);
        }
      }
      setErrorMessage('');
      setSuccessMessage('');
    }
  }, [isOpen, initialOriginal, initialCategory, renames]);

  // Compute occurrences count in sourceCode
  const countOccurrences = (target: string): number => {
    if (!target || !sourceCode) return 0;
    try {
      const isWord = /^[a-zA-Z0-9_]+$/.test(target);
      const re = isWord
        ? new RegExp(`\\b${target}\\b`, 'gi')
        : new RegExp(target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const matches = sourceCode.match(re);
      return matches ? matches.length : 0;
    } catch {
      return 0;
    }
  };

  const handleApply = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    const origTrim = original.trim();
    const renTrim = renamed.trim();

    if (!origTrim) {
      setErrorMessage('Please specify the original symbol or string to rename.');
      return;
    }
    if (!renTrim) {
      setErrorMessage('Please provide a new replacement name.');
      return;
    }
    if (origTrim === renTrim) {
      setErrorMessage('The new name must be different from the original.');
      return;
    }

    addOrUpdateRename(origTrim, renTrim, category, binaryScope);
    setSuccessMessage(`Successfully renamed "${origTrim}" to "${renTrim}" across all views.`);
    setOriginal('');
    setRenamed('');
    setTimeout(() => setSuccessMessage(''), 3000);
  };

  const handleQuickSelect = (name: string, cat: SymbolCategory) => {
    setOriginal(name);
    setCategory(cat);
    const existing = renames.find((r) => r.original.toLowerCase() === name.toLowerCase());
    setRenamed(existing ? existing.renamed : '');
  };

  const filteredRenames = useMemo(() => {
    if (!filterSearch) return renames;
    const q = filterSearch.toLowerCase();
    return renames.filter(
      (r) =>
        r.original.toLowerCase().includes(q) ||
        r.renamed.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q)
    );
  }, [renames, filterSearch]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-[9999] bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4 animate-fade-in"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[90vh] animate-modal-fade text-slate-900"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-200 flex items-center justify-between bg-slate-50/70 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shadow-2xs">
              <Edit3 className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Rename Symbols, Functions & Variables
              </h3>
              <p className="text-xs text-slate-500 font-mono">
                Changes propagate instantly to Decompiler, BinDiff CFG & Disassembly
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-700 hover:bg-slate-200/60 rounded-xl transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 min-h-0 text-xs">
          {/* Success or Error Alert */}
          {errorMessage && (
            <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 flex items-center gap-2 animate-shake">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMessage}</span>
            </div>
          )}
          {successMessage && (
            <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 flex items-center gap-2">
              <Check className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Form: Add or Edit Rename */}
          <form onSubmit={handleApply} className="bg-slate-50 p-4 rounded-2xl border border-slate-200 space-y-4">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-800 uppercase text-[10px] tracking-wider font-mono">
                1. Select Item Category
              </span>
              <div className="flex items-center bg-white p-0.5 rounded-lg border border-slate-200 shadow-2xs">
                <button
                  type="button"
                  onClick={() => setCategory('function')}
                  className={`px-2.5 py-1 rounded-md font-semibold flex items-center gap-1.5 transition-colors ${
                    category === 'function'
                      ? 'bg-indigo-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Function</span>
                </button>
                <button
                  type="button"
                  onClick={() => setCategory('variable')}
                  className={`px-2.5 py-1 rounded-md font-semibold flex items-center gap-1.5 transition-colors ${
                    category === 'variable'
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Hash className="w-3.5 h-3.5" />
                  <span>Variable</span>
                </button>
                <button
                  type="button"
                  onClick={() => setCategory('string')}
                  className={`px-2.5 py-1 rounded-md font-semibold flex items-center gap-1.5 transition-colors ${
                    category === 'string'
                      ? 'bg-amber-600 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <Type className="w-3.5 h-3.5" />
                  <span>String</span>
                </button>
              </div>
            </div>

            {/* Quick Pick Chips */}
            <div>
              <span className="text-[10px] font-mono text-slate-500 block mb-1.5 font-semibold">
                Quick Select from Analyzed Binary:
              </span>
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto p-1.5 bg-white rounded-xl border border-slate-200">
                {category === 'function' &&
                  (discoveredFunctions.length > 0 ? (
                    discoveredFunctions.map((fn, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleQuickSelect(fn, 'function')}
                        className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors border ${
                          original === fn
                            ? 'bg-indigo-50 border-indigo-300 text-indigo-700 font-bold'
                            : 'bg-slate-50 hover:bg-indigo-50/60 border-slate-200 text-slate-700'
                        }`}
                      >
                        {fn}
                      </button>
                    ))
                  ) : (
                    <span className="text-slate-400 italic text-[11px]">No functions discovered yet</span>
                  ))}

                {category === 'variable' &&
                  (discoveredVariables.length > 0 ? (
                    discoveredVariables.map((v, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleQuickSelect(v, 'variable')}
                        className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors border ${
                          original === v
                            ? 'bg-blue-50 border-blue-300 text-blue-700 font-bold'
                            : 'bg-slate-50 hover:bg-blue-50/60 border-slate-200 text-slate-700'
                        }`}
                      >
                        {v}
                      </button>
                    ))
                  ) : (
                    <span className="text-slate-400 italic text-[11px]">No variables discovered yet</span>
                  ))}

                {category === 'string' &&
                  (discoveredStrings.length > 0 ? (
                    discoveredStrings.map((str, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => handleQuickSelect(str, 'string')}
                        className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors border truncate max-w-[200px] ${
                          original === str
                            ? 'bg-amber-50 border-amber-300 text-amber-800 font-bold'
                            : 'bg-slate-50 hover:bg-amber-50/60 border-slate-200 text-slate-700'
                        }`}
                        title={str}
                      >
                        "{str}"
                      </button>
                    ))
                  ) : (
                    <span className="text-slate-400 italic text-[11px]">No strings discovered yet</span>
                  ))}
              </div>
            </div>

            {/* Inputs: Target & Replacement */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div>
                <label className="block text-[10px] font-bold text-slate-700 uppercase font-mono mb-1">
                  Original Target ({category})
                </label>
                <div className="relative">
                  <input
                    type="text"
                    value={original}
                    onChange={(e) => setOriginal(e.target.value)}
                    placeholder={
                      category === 'function'
                        ? 'e.g. entry_point or loc_1069'
                        : category === 'variable'
                        ? 'e.g. result or var_4'
                        : 'e.g. http://evil.com'
                    }
                    className="w-full px-3 py-2 bg-white rounded-xl border border-slate-300 text-slate-900 font-mono text-xs focus:outline-hidden focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 shadow-2xs"
                  />
                  {original && (
                    <span className="absolute right-2 top-2 px-1.5 py-0.5 rounded text-[9px] font-mono bg-slate-100 text-slate-500 border border-slate-200">
                      {countOccurrences(original)} hits
                    </span>
                  )}
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-bold text-slate-700 uppercase font-mono mb-1">
                  New Renamed Name
                </label>
                <input
                  type="text"
                  value={renamed}
                  onChange={(e) => setRenamed(e.target.value)}
                  placeholder={
                    category === 'function'
                      ? 'e.g. MalwareMain'
                      : category === 'variable'
                      ? 'e.g. dwStatus'
                      : 'e.g. STR_C2_URL'
                  }
                  className="w-full px-3 py-2 bg-white rounded-xl border border-slate-300 text-slate-900 font-mono text-xs focus:outline-hidden focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 shadow-2xs"
                />
              </div>
            </div>

            {/* Live Preview & Submit */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
              {original && renamed ? (
                <div className="flex items-center gap-2 font-mono text-[11px] text-slate-600 bg-white px-3 py-1.5 rounded-xl border border-slate-200">
                  <span className="line-through text-slate-400 font-semibold">{original}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-indigo-500" />
                  <span className="text-indigo-600 font-bold">{renamed}</span>
                </div>
              ) : (
                <span className="text-[11px] text-slate-400 italic">
                  Enter target and replacement name to preview changes
                </span>
              )}

              <button
                type="submit"
                className="w-full sm:w-auto px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-bold flex items-center justify-center gap-1.5 shadow-xs transition-colors cursor-pointer"
              >
                <Check className="w-4 h-4" />
                <span>Apply Rename Everywhere</span>
              </button>
            </div>
          </form>

          {/* Active Renames Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Tag className="w-4 h-4 text-slate-500" />
                <h4 className="text-xs font-bold text-slate-900 uppercase font-mono">
                  Active Renamed Items ({renames.length})
                </h4>
              </div>

              {renames.length > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    if (window.confirm('Reset all symbol renames back to their original binary identifiers?')) {
                      clearRenames();
                    }
                  }}
                  className="text-rose-600 hover:text-rose-700 text-[11px] font-semibold flex items-center gap-1 hover:underline cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset All</span>
                </button>
              )}
            </div>

            {renames.length > 5 && (
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  value={filterSearch}
                  onChange={(e) => setFilterSearch(e.target.value)}
                  placeholder="Filter active renames..."
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono focus:outline-hidden focus:border-indigo-500"
                />
              </div>
            )}

            {filteredRenames.length === 0 ? (
              <div className="p-6 text-center bg-slate-50/50 rounded-2xl border border-dashed border-slate-200 text-slate-400">
                <Layers className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                <p className="font-medium text-slate-600">No custom symbol renames yet</p>
                <p className="text-[11px] text-slate-400 mt-1 max-w-sm mx-auto">
                  Select a function, variable, or string above to rename all occurrences across the C/C++ Decompiler, BinDiff CFG, and disassembly listings.
                </p>
              </div>
            ) : (
              <div className="border border-slate-200 rounded-2xl overflow-hidden shadow-2xs divide-y divide-slate-100">
                {filteredRenames.map((r) => {
                  const hits = countOccurrences(r.renamed) || countOccurrences(r.original);
                  return (
                    <div
                      key={r.id}
                      className="p-3 bg-white hover:bg-slate-50/80 transition-colors flex items-center justify-between gap-3"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase shrink-0 ${
                            r.category === 'function'
                              ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                              : r.category === 'variable'
                              ? 'bg-blue-50 text-blue-700 border border-blue-200'
                              : 'bg-amber-50 text-amber-800 border border-amber-200'
                          }`}
                        >
                          {r.category}
                        </span>

                        <div className="font-mono text-xs truncate">
                          <span className="text-slate-400 line-through mr-1.5">{r.original}</span>
                          <span className="text-slate-300 mr-1.5">➔</span>
                          <span className="font-bold text-slate-900 bg-indigo-50/70 text-indigo-700 px-1.5 py-0.5 rounded border border-indigo-200/50">
                            {r.renamed}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {hits > 0 && (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-100 text-slate-600 border border-slate-200">
                            {hits} {hits === 1 ? 'hit' : 'hits'}
                          </span>
                        )}

                        <button
                          type="button"
                          onClick={() => {
                            setOriginal(r.original);
                            setRenamed(r.renamed);
                            setCategory(r.category);
                          }}
                          className="p-1 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors cursor-pointer"
                          title="Edit Rename"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>

                        <button
                          type="button"
                          onClick={() => removeRename(r.id)}
                          className="p-1 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors cursor-pointer"
                          title="Remove Rename (Revert to Original)"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between shrink-0">
          <div className="text-[11px] text-slate-500 font-mono">
            <span>Tip: Click on any symbol or variable in the C/C++ pseudocode to quickly rename it.</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 rounded-xl font-semibold text-xs transition-colors cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
