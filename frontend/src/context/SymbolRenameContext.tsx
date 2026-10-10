import React, { createContext, useContext, useState, useEffect, useMemo, useCallback } from 'react';

export type SymbolCategory = 'function' | 'variable' | 'string';

export interface SymbolRename {
  id: string;
  original: string;
  renamed: string;
  category: SymbolCategory;
  binaryScope?: string; // Optional: specific filename or jobId, or 'all'
  timestamp: number;
}

export interface SymbolRenameContextType {
  renames: SymbolRename[];
  addOrUpdateRename: (
    original: string,
    renamed: string,
    category: SymbolCategory,
    binaryScope?: string
  ) => void;
  removeRename: (idOrOriginal: string) => void;
  clearRenames: () => void;
  getRenamed: (name: string, binaryScope?: string) => string;
  isRenamed: (name: string, binaryScope?: string) => boolean;
  applyToCode: (text: string, binaryScope?: string) => string;
  applyToInstruction: <T extends Record<string, any>>(inst: T, binaryScope?: string) => T;
}

const STORAGE_KEY = 'filesanitizer_symbol_renames_v1';

const SymbolRenameContext = createContext<SymbolRenameContextType | undefined>(undefined);

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export const SymbolRenameProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [renames, setRenames] = useState<SymbolRename[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (e) {
      console.warn('Failed to load symbol renames from localStorage', e);
    }
    return [];
  });

  // Save to localStorage whenever renames change
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(renames));
    } catch (e) {
      console.warn('Failed to save symbol renames to localStorage', e);
    }
  }, [renames]);

  const addOrUpdateRename = useCallback(
    (original: string, renamed: string, category: SymbolCategory, binaryScope: string = 'all') => {
      const origTrim = original.trim();
      const renTrim = renamed.trim();
      if (!origTrim || !renTrim) return;

      setRenames((prev) => {
        // If renaming back to original, remove the entry
        if (origTrim === renTrim) {
          return prev.filter((r) => r.original !== origTrim);
        }

        const existingIdx = prev.findIndex((r) => r.original.toLowerCase() === origTrim.toLowerCase());
        const newItem: SymbolRename = {
          id: existingIdx >= 0 ? prev[existingIdx].id : `sym_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
          original: origTrim,
          renamed: renTrim,
          category,
          binaryScope,
          timestamp: Date.now()
        };

        if (existingIdx >= 0) {
          const next = [...prev];
          next[existingIdx] = newItem;
          return next;
        } else {
          return [...prev, newItem];
        }
      });
    },
    []
  );

  const removeRename = useCallback((idOrOriginal: string) => {
    setRenames((prev) =>
      prev.filter(
        (r) =>
          r.id !== idOrOriginal &&
          r.original.toLowerCase() !== idOrOriginal.toLowerCase() &&
          r.renamed.toLowerCase() !== idOrOriginal.toLowerCase()
      )
    );
  }, []);

  const clearRenames = useCallback(() => {
    setRenames([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {}
  }, []);

  const getRenamed = useCallback(
    (name: string, binaryScope?: string): string => {
      if (!name) return name;
      const target = name.trim();
      const found = renames.find(
        (r) =>
          r.original.toLowerCase() === target.toLowerCase() &&
          (!binaryScope || r.binaryScope === 'all' || r.binaryScope === binaryScope)
      );
      return found ? found.renamed : name;
    },
    [renames]
  );

  const isRenamed = useCallback(
    (name: string, binaryScope?: string): boolean => {
      if (!name) return false;
      const target = name.trim();
      return renames.some(
        (r) =>
          r.original.toLowerCase() === target.toLowerCase() &&
          (!binaryScope || r.binaryScope === 'all' || r.binaryScope === binaryScope)
      );
    },
    [renames]
  );

  // Compile replacement pipeline sorted by length (descending) to avoid partial sub-token collisions
  const applyToCode = useCallback(
    (text: string, binaryScope?: string): string => {
      if (!text || renames.length === 0) return text;

      const applicable = renames
        .filter((r) => !binaryScope || r.binaryScope === 'all' || r.binaryScope === binaryScope)
        .sort((a, b) => b.original.length - a.original.length);

      let result = text;
      for (const r of applicable) {
        if (!r.original || !r.renamed) continue;

        // Check if string literal replacement
        if (r.category === 'string') {
          // Replace both quoted and raw instances
          const rawEsc = escapeRegex(r.original);
          result = result.replace(new RegExp(rawEsc, 'g'), r.renamed);
        } else {
          // Function or variable: use word boundary
          const isWordOnly = /^[a-zA-Z0-9_]+$/.test(r.original);
          if (isWordOnly) {
            const re = new RegExp(`\\b${escapeRegex(r.original)}\\b`, 'g');
            result = result.replace(re, r.renamed);
          } else {
            const re = new RegExp(escapeRegex(r.original), 'g');
            result = result.replace(re, r.renamed);
          }
        }
      }
      return result;
    },
    [renames]
  );

  const applyToInstruction = useCallback(
    <T extends Record<string, any>>(inst: T, binaryScope?: string): T => {
      if (!inst) return inst;
      const operandsText = (inst as any).op_str ?? (inst as any).operands ?? '';
      if (!operandsText || typeof operandsText !== 'string') return inst;
      const renamedOperands = applyToCode(operandsText, binaryScope);
      const res: any = { ...inst };
      if ('op_str' in inst || !('operands' in inst)) {
        res.op_str = renamedOperands;
      }
      if ('operands' in inst || !('op_str' in inst)) {
        res.operands = renamedOperands;
      }
      return res as T;
    },
    [applyToCode]
  );

  const value = useMemo(
    () => ({
      renames,
      addOrUpdateRename,
      removeRename,
      clearRenames,
      getRenamed,
      isRenamed,
      applyToCode,
      applyToInstruction
    }),
    [renames, addOrUpdateRename, removeRename, clearRenames, getRenamed, isRenamed, applyToCode, applyToInstruction]
  );

  return <SymbolRenameContext.Provider value={value}>{children}</SymbolRenameContext.Provider>;
};

export const useSymbolRenames = (): SymbolRenameContextType => {
  const ctx = useContext(SymbolRenameContext);
  if (!ctx) {
    // Graceful fallback dummy if rendered outside provider
    return {
      renames: [],
      addOrUpdateRename: () => {},
      removeRename: () => {},
      clearRenames: () => {},
      getRenamed: (n: string) => n,
      isRenamed: () => false,
      applyToCode: (t: string) => t,
      applyToInstruction: (i) => i
    };
  }
  return ctx;
};
