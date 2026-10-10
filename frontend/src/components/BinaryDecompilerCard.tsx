import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  FileCode,
  Copy,
  Check,
  Download,
  Terminal,
  ShieldAlert,
  Split,
  Layers,
  Sparkles,
  Search,
  Code2,
  Table,
  Edit3,
  GitFork,
  Hash,
  Network,
  CheckSquare,
  Square
} from 'lucide-react';
import { DecompiledFunction, BinaryInfo, CallGraphData } from '../types';
import { decompileInstructions, buildBidirectionalCodeMapping } from '../utils/decompilerEngine';
import { useSymbolRenames, SymbolCategory } from '../context/SymbolRenameContext';
import { SymbolRenameModal } from './SymbolRenameModal';
import { XrefsModal } from './XrefsModal';
import { FunctionCallGraphView } from './FunctionCallGraphView';
import { ApiHashingInspectorView } from './ApiHashingInspectorView';
import { SingleBinaryFlowCanvas } from './SingleBinaryFlowCanvas';
import { buildBasicBlocksFromInstructions } from '../utils/cfgEngine';
import { buildClientXrefs, lookupXrefsForSymbol } from '../utils/xrefEngine';
import { scanInstructionsForApiHashes } from '../utils/apiHashingDetector';

interface BinaryDecompilerCardProps {
  binaryInfo: BinaryInfo;
  filename?: string;
  defaultViewMode?: 'decompiler' | 'side_by_side' | 'assembly' | 'call_graph' | 'api_hashing' | 'flow_canvas';
}

export const BinaryDecompilerCard: React.FC<BinaryDecompilerCardProps> = ({
  binaryInfo,
  filename = 'binary.exe',
  defaultViewMode = 'decompiler'
}) => {
  const {
    renames,
    getRenamed,
    isRenamed,
    applyToCode,
    applyToInstruction
  } = useSymbolRenames();

  const [viewMode, setViewMode] = useState<'decompiler' | 'side_by_side' | 'assembly' | 'call_graph' | 'api_hashing' | 'flow_canvas'>(defaultViewMode);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isRenameModalOpen, setIsRenameModalOpen] = useState<boolean>(false);
  const [renameTargetSymbol, setRenameTargetSymbol] = useState<string>('');
  const [renameTargetCategory, setRenameTargetCategory] = useState<SymbolCategory>('function');

  // XREFs modal state
  const [isXrefsModalOpen, setIsXrefsModalOpen] = useState<boolean>(false);
  const [xrefsTargetSymbol, setXrefsTargetSymbol] = useState<string>('');

  const handleOpenRename = (symbol: string = '', cat: SymbolCategory = 'function') => {
    setRenameTargetSymbol(symbol);
    setRenameTargetCategory(cat);
    setIsRenameModalOpen(true);
  };

  // Obtain decompilation from backend or synthesize on the client-side
  const decomp: DecompiledFunction = useMemo(() => {
    if (binaryInfo.decompilation && binaryInfo.decompilation.code) {
      return binaryInfo.decompilation;
    }
    const insts = binaryInfo.disassembly?.instructions || [];
    const ep = binaryInfo.disassembly?.entry_point || binaryInfo.entry_point || '0x401000';
    const importsArray: Array<{ dll?: string; name?: string; api?: string; is_suspicious?: boolean }> = [];
    if (binaryInfo.imports) {
      Object.entries(binaryInfo.imports).forEach(([dll, funcs]) => {
        funcs.forEach((f) => {
          importsArray.push({
            dll,
            name: f.name,
            api: f.name,
            is_suspicious: f.is_suspicious
          });
        });
      });
    }
    return decompileInstructions(
      insts,
      ep,
      'entry_point',
      binaryInfo.architecture || 'x86-64',
      importsArray
    );
  }, [binaryInfo]);

  // Discovered symbols for quick selection in rename modal
  const discoveredFunctions = useMemo(() => {
    const set = new Set<string>();
    if (decomp.function_name) set.add(decomp.function_name);
    (binaryInfo.disassembly?.instructions || []).forEach((inst) => {
      if (inst.mnemonic?.startsWith('j') || inst.mnemonic === 'call') {
        if (inst.op_str && /^(loc_|sub_|0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*)/.test(inst.op_str)) {
          set.add(inst.op_str);
        }
      }
    });
    const branchMatches = decomp.code.match(/loc_[0-9a-fA-F]+/g) || [];
    branchMatches.forEach((b) => set.add(b));
    return Array.from(set);
  }, [decomp, binaryInfo]);

  const discoveredVariables = useMemo(() => {
    const set = new Set<string>();
    (decomp.variables || []).forEach((v) => set.add(v.name));
    (decomp.parameters || []).forEach((p) => set.add(p.name));
    const varMatches = decomp.code.match(/\b(result|counter|ppeb|var_\w+|arg\w+|condition_\d+)\b/g) || [];
    varMatches.forEach((v) => set.add(v));
    return Array.from(set);
  }, [decomp]);

  const discoveredStrings = useMemo(() => {
    const set = new Set<string>();
    if (binaryInfo.strings) {
      const allSample = Array.isArray(binaryInfo.strings.all_sample)
        ? binaryInfo.strings.all_sample
        : Array.isArray(binaryInfo.strings)
        ? binaryInfo.strings
        : [];
      allSample.slice(0, 50).forEach((s: any) => {
        const val = typeof s === 'string' ? s : s.value;
        if (val && val.length > 2 && val.length < 50) set.add(val);
      });
    }
    const strMatches = decomp.code.match(/"([^"\\]|\\.)*"/g) || [];
    strMatches.forEach((s) => set.add(s.replace(/^"|"$/g, '')));
    return Array.from(set);
  }, [binaryInfo, decomp]);

  // Apply symbol renames to all decompiled outputs
  const activeFunctionName = useMemo(
    () => getRenamed(decomp.function_name),
    [getRenamed, decomp.function_name]
  );

  const activeSignature = useMemo(
    () => applyToCode(decomp.signature),
    [applyToCode, decomp.signature]
  );

  const activeCode = useMemo(
    () => applyToCode(decomp.code),
    [applyToCode, decomp.code]
  );

  const lines = useMemo(() => activeCode.split('\n'), [activeCode]);

  const activeInstructions = useMemo(() => {
    return (binaryInfo.disassembly?.instructions || []).map((inst) => applyToInstruction(inst));
  }, [binaryInfo.disassembly, applyToInstruction]);

  // Bidirectional code mapping between ASM instructions and C pseudocode lines
  const codeMapping = useMemo(() => {
    if (decomp.inst_to_lines && decomp.line_to_insts) {
      return {
        instToLines: decomp.inst_to_lines,
        lineToInsts: decomp.line_to_insts
      };
    }
    return buildBidirectionalCodeMapping(activeInstructions, lines);
  }, [decomp.inst_to_lines, decomp.line_to_insts, activeInstructions, lines]);

  // Synchronized bidirectional selection in Split (Asm + C) mode
  const [selectedInstIndices, setSelectedInstIndices] = useState<number[]>([]);
  const [selectedCodeLines, setSelectedCodeLines] = useState<number[]>([]);
  const [lastSelectedInstIndex, setLastSelectedInstIndex] = useState<number | null>(null);
  const [lastSelectedCodeLine, setLastSelectedCodeLine] = useState<number | null>(null);
  const [selectionSource, setSelectionSource] = useState<'asm' | 'c' | null>(null);
  const [isMultiSelectMode, setIsMultiSelectMode] = useState<boolean>(false);
  const [isDraggingSelect, setIsDraggingSelect] = useState<'asm' | 'c' | null>(null);
  const [dragAnchorIdx, setDragAnchorIdx] = useState<number | null>(null);

  const asmContainerRef = useRef<HTMLDivElement>(null);
  const codeContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll opposite pane to first mapped row
  const autoScrollToMappedLine = (targetLine: number) => {
    if (!codeContainerRef.current) return;
    const el = codeContainerRef.current.querySelector(`[data-line-num="${targetLine}"]`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  };

  const autoScrollToMappedInst = (targetIdx: number) => {
    if (!asmContainerRef.current) return;
    const el = asmContainerRef.current.querySelector(`[data-inst-idx="${targetIdx}"]`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  };

  // Terminate drag-selection on global mouse up
  useEffect(() => {
    const handleGlobalMouseUp = () => {
      setIsDraggingSelect(null);
    };
    window.addEventListener('mouseup', handleGlobalMouseUp);
    return () => window.removeEventListener('mouseup', handleGlobalMouseUp);
  }, []);

  // Update selection originating from ASM side and compute mapped C lines
  const updateAsmSelection = (instIndices: number[]) => {
    setSelectedInstIndices(instIndices);
    setSelectionSource('asm');
    const mappedLines = new Set<number>();
    instIndices.forEach((instIdx) => {
      (codeMapping.instToLines[instIdx] || []).forEach((l) => mappedLines.add(l));
    });
    const sortedLines = Array.from(mappedLines).sort((a, b) => a - b);
    setSelectedCodeLines(sortedLines);

    if (sortedLines.length > 0) {
      autoScrollToMappedLine(sortedLines[0]);
    }
  };

  // Update selection originating from C side and compute mapped ASM instructions
  const updateCodeSelection = (codeLineNums: number[]) => {
    setSelectedCodeLines(codeLineNums);
    setSelectionSource('c');
    const mappedInsts = new Set<number>();
    codeLineNums.forEach((ln) => {
      (codeMapping.lineToInsts[ln] || []).forEach((instIdx) => mappedInsts.add(instIdx));
    });
    const sortedInsts = Array.from(mappedInsts).sort((a, b) => a - b);
    setSelectedInstIndices(sortedInsts);

    if (sortedInsts.length > 0) {
      autoScrollToMappedInst(sortedInsts[0]);
    }
  };

  // ASM row mouse interactions
  const handleAsmRowMouseDown = (idx: number, e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDraggingSelect('asm');
    setDragAnchorIdx(idx);

    if (e.shiftKey && lastSelectedInstIndex !== null) {
      const start = Math.min(lastSelectedInstIndex, idx);
      const end = Math.max(lastSelectedInstIndex, idx);
      const range = Array.from({ length: end - start + 1 }, (_, i) => start + i);
      const nextSelected = Array.from(new Set([...selectedInstIndices, ...range])).sort((a, b) => a - b);
      updateAsmSelection(nextSelected);
    } else if (e.metaKey || e.ctrlKey || isMultiSelectMode) {
      const nextSelected = selectedInstIndices.includes(idx)
        ? selectedInstIndices.filter((i) => i !== idx)
        : [...selectedInstIndices, idx].sort((a, b) => a - b);
      setLastSelectedInstIndex(idx);
      updateAsmSelection(nextSelected);
    } else {
      setLastSelectedInstIndex(idx);
      updateAsmSelection([idx]);
    }
  };

  const handleAsmRowMouseEnter = (idx: number) => {
    if (isDraggingSelect !== 'asm' || dragAnchorIdx === null) return;
    const start = Math.min(dragAnchorIdx, idx);
    const end = Math.max(dragAnchorIdx, idx);
    const range = Array.from({ length: end - start + 1 }, (_, i) => start + i);
    updateAsmSelection(range);
  };

  const handleAsmRowClick = (idx: number, e: React.MouseEvent) => {
    if (selectedInstIndices.length > 1 && selectedInstIndices.includes(idx)) {
      return;
    }
    handleAsmRowMouseDown(idx, e);
  };

  // C code line mouse interactions
  const handleCodeLineMouseDown = (lineNum: number, e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsDraggingSelect('c');
    setDragAnchorIdx(lineNum);

    if (e.shiftKey && lastSelectedCodeLine !== null) {
      const start = Math.min(lastSelectedCodeLine, lineNum);
      const end = Math.max(lastSelectedCodeLine, lineNum);
      const range = Array.from({ length: end - start + 1 }, (_, i) => start + i);
      const nextSelected = Array.from(new Set([...selectedCodeLines, ...range])).sort((a, b) => a - b);
      updateCodeSelection(nextSelected);
    } else if (e.metaKey || e.ctrlKey || isMultiSelectMode) {
      const nextSelected = selectedCodeLines.includes(lineNum)
        ? selectedCodeLines.filter((l) => l !== lineNum)
        : [...selectedCodeLines, lineNum].sort((a, b) => a - b);
      setLastSelectedCodeLine(lineNum);
      updateCodeSelection(nextSelected);
    } else {
      setLastSelectedCodeLine(lineNum);
      updateCodeSelection([lineNum]);
    }
  };

  const handleCodeLineMouseEnter = (lineNum: number) => {
    if (isDraggingSelect !== 'c' || dragAnchorIdx === null) return;
    const start = Math.min(dragAnchorIdx, lineNum);
    const end = Math.max(dragAnchorIdx, lineNum);
    const range = Array.from({ length: end - start + 1 }, (_, i) => start + i);
    updateCodeSelection(range);
  };

  const handleCodeLineClick = (lineNum: number, e: React.MouseEvent) => {
    if (selectedCodeLines.length > 1 && selectedCodeLines.includes(lineNum)) {
      return;
    }
    handleCodeLineMouseDown(lineNum, e);
  };

  const handleSelectAllAsm = () => {
    const all = activeInstructions.map((_, i) => i);
    setLastSelectedInstIndex(0);
    updateAsmSelection(all);
  };

  const handleSelectAllCode = () => {
    const all = lines.map((_, i) => i + 1);
    setLastSelectedCodeLine(1);
    updateCodeSelection(all);
  };

  const handleClearSelection = () => {
    setSelectedInstIndices([]);
    setSelectedCodeLines([]);
    setLastSelectedInstIndex(null);
    setLastSelectedCodeLine(null);
    setSelectionSource(null);
    setIsDraggingSelect(null);
  };

  // Compute or obtain API Hashing Matches
  const apiHashingMatches = useMemo(() => {
    if (binaryInfo.api_hashing && binaryInfo.api_hashing.length > 0) {
      return binaryInfo.api_hashing;
    }
    const rawInsts = binaryInfo.disassembly?.instructions || [];
    return scanInstructionsForApiHashes(rawInsts);
  }, [binaryInfo]);

  // Compute or obtain XREFs
  const xrefsData = useMemo(() => {
    if (binaryInfo.xrefs && binaryInfo.xrefs.total_xrefs > 0) {
      return binaryInfo.xrefs;
    }
    const rawInsts = binaryInfo.disassembly?.instructions || [];
    const rawStringsList = ((binaryInfo.strings as any)?.items || binaryInfo.strings?.all_sample || []) as any[];
    const knownStrings = rawStringsList.map((s: any, idx: number) => ({
      offset: typeof s === 'object' ? (s.offset || s.rva) : (0x400000 + idx * 0x20),
      value: typeof s === 'object' ? (s.value || s.string || '') : String(s)
    }));
    const flatImports: Array<{ api?: string; name?: string }> = [];
    if (binaryInfo.imports) {
      Object.values(binaryInfo.imports).forEach((list) => {
        list.forEach((imp) => flatImports.push({ api: imp.name, name: imp.name }));
      });
    }
    return buildClientXrefs(rawInsts, knownStrings, flatImports);
  }, [binaryInfo]);

  // Compute or obtain Visual Call Graph
  const callGraphData: CallGraphData = useMemo(() => {
    if (binaryInfo.call_graph && binaryInfo.call_graph.nodes.length > 0) {
      return binaryInfo.call_graph;
    }
    const rawInsts = binaryInfo.disassembly?.instructions || [];
    const ep = binaryInfo.disassembly?.entry_point || binaryInfo.entry_point || '0x401000';
    const flatImports: Array<{ api?: string; name?: string }> = [];
    if (binaryInfo.imports) {
      Object.values(binaryInfo.imports).forEach((list) => {
        list.forEach((imp) => flatImports.push({ api: imp.name, name: imp.name }));
      });
    }

    const nodesMap = new Map<string, any>();
    const edges: any[] = [];
    const rootId = `func_${ep.replace('0x', '')}`;
    nodesMap.set(rootId, {
      id: rootId,
      label: activeFunctionName || 'entry_point',
      address: ep,
      node_type: 'ENTRY_POINT',
      risk: 'info',
      instruction_count: rawInsts.length,
      suspicious_flags: [],
      is_root: true,
      in_degree: 0,
      out_degree: 0
    });

    rawInsts.forEach((inst) => {
      if (inst.mnemonic?.toLowerCase() === 'call') {
        const tgt = inst.op_str.replace(/[\[\]]/g, '').replace(/dword ptr |qword ptr /g, '').trim();
        const tgtId = `node_${tgt.toLowerCase().replace(/[^a-z0-9_]/g, '_')}`;
        if (!nodesMap.has(tgtId)) {
          const isImp = flatImports.some((i) => i.api?.toLowerCase() === tgt.toLowerCase());
          nodesMap.set(tgtId, {
            id: tgtId,
            label: tgt,
            address: tgt.startsWith('0x') ? tgt : 'N/A',
            node_type: isImp ? 'IMPORT_API' : 'INTERNAL',
            risk: isImp ? 'high' : 'info',
            instruction_count: 0,
            suspicious_flags: isImp ? [`Invokes Win32 API ${tgt}`] : [],
            is_root: false,
            in_degree: 0,
            out_degree: 0
          });
        }
        edges.push({
          id: `edge_${edges.length + 1}`,
          source: rootId,
          target: tgtId,
          call_type: 'CALL',
          instruction_address: inst.address,
          count: 1
        });
      }
    });

    // Add API hashing nodes
    apiHashingMatches.forEach((m) => {
      const hashId = `hash_${m.resolved_api.toLowerCase()}`;
      if (!nodesMap.has(hashId)) {
        nodesMap.set(hashId, {
          id: hashId,
          label: `${m.resolved_api} (${m.algorithm})`,
          address: m.address || 'dynamic',
          node_type: 'RESOLVED_HASH',
          risk: m.severity || 'high',
          instruction_count: 1,
          suspicious_flags: [`Resolved via ${m.algorithm} ${m.hash_hex}`],
          is_root: false,
          in_degree: 1,
          out_degree: 0
        });
        edges.push({
          id: `edge_${edges.length + 1}`,
          source: rootId,
          target: hashId,
          call_type: 'DYNAMIC_RESOLVE',
          instruction_address: m.address,
          count: 1
        });
      }
    });

    // If no direct 'call' instructions were in entry disassembly, link available imported APIs as direct invocations
    if (edges.length === 0 && flatImports.length > 0) {
      flatImports.slice(0, 8).forEach((imp, iIdx) => {
        const apiName = imp.name || imp.api || `Import_${iIdx + 1}`;
        const tgtId = `node_imp_${apiName.toLowerCase().replace(/[^a-z0-9_]/g, '_')}`;
        if (!nodesMap.has(tgtId)) {
          const isHighRisk = ['virtualalloc', 'writeprocessmemory', 'createremotethread', 'loadlibrary', 'getprocaddress', 'winexec', 'createprocess', 'urldownloadtofile'].some((k) => apiName.toLowerCase().includes(k));
          nodesMap.set(tgtId, {
            id: tgtId,
            label: apiName,
            address: 'IAT Entry',
            node_type: 'IMPORT_API',
            risk: isHighRisk ? 'critical' : 'high',
            instruction_count: 1,
            suspicious_flags: isHighRisk ? [`High-risk Win32 API invocation (${apiName})`] : [`Imported library API (${apiName})`],
            is_root: false,
            in_degree: 0,
            out_degree: 0
          });
          edges.push({
            id: `edge_imp_${iIdx + 1}`,
            source: rootId,
            target: tgtId,
            call_type: 'CALL',
            count: 1
          });
        }
      });
    }

    // Accurately compute degrees for all graph nodes
    edges.forEach((e) => {
      const srcNode = nodesMap.get(e.source);
      const tgtNode = nodesMap.get(e.target);
      if (srcNode) srcNode.out_degree = (srcNode.out_degree || 0) + 1;
      if (tgtNode) tgtNode.in_degree = (tgtNode.in_degree || 0) + 1;
    });

    return {
      nodes: Array.from(nodesMap.values()),
      edges,
      metrics: {
        total_functions: nodesMap.size,
        total_calls: edges.length,
        has_recursion: false,
        high_risk_nodes_count: Array.from(nodesMap.values()).filter((n) => n.risk === 'critical' || n.risk === 'high').length
      }
    };
  }, [binaryInfo, activeFunctionName, apiHashingMatches]);

  // Compute Control Flow Graph basic blocks and edges for Single Binary Flow Canvas
  const singleCfgData = useMemo(() => {
    if ((binaryInfo as any).cfg && (binaryInfo as any).cfg.blocks?.length > 0) {
      return (binaryInfo as any).cfg;
    }
    const rawInsts = binaryInfo.disassembly?.instructions || [];
    const ep = binaryInfo.disassembly?.entry_point || binaryInfo.entry_point || '0x401000';
    return buildBasicBlocksFromInstructions(rawInsts, ep);
  }, [binaryInfo]);

  const handleOpenXrefs = (symbol: string = '') => {
    setXrefsTargetSymbol(symbol || activeFunctionName || 'entry_point');
    setIsXrefsModalOpen(true);
  };

  const handleJumpToAddress = (address: string) => {
    setViewMode('assembly');
    setSearchQuery(address);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(activeCode);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleDownloadC = () => {
    const blob = new Blob([activeCode], { type: 'text/x-c;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${filename.replace(/\.[^/.]+$/, '')}_decompiled.c`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Syntax highlighting for C/C++ pseudocode with interactive token renaming
  const renderHighlightedLine = (line: string, _lineNum?: number) => {
    // Comments
    if (line.trim().startsWith('/*') || line.trim().startsWith('*') || line.trim().startsWith('//')) {
      return <span className="text-emerald-700 italic">{line}</span>;
    }

    // Directives
    if (line.trim().startsWith('#')) {
      return <span className="text-purple-700 font-semibold">{line}</span>;
    }

    // Tokenized line rendering
    const tokens = line.split(
      /(\b(?:int|void|char|uint32_t|PPEB|HANDLE|BOOL|SIZE_T|DWORD|FARPROC|HMODULE|if|else|while|for|return|break|continue|switch|case|default|struct|true|false)\b|"[^"]*"|'[^']*'|0x[0-9a-fA-F]+|\b\d+\b|\/\/.*$)/g
    );

    return (
      <>
        {tokens.map((token, tIdx) => {
          if (!token) return null;
          if (token.startsWith('//')) {
            return <span key={tIdx} className="text-emerald-700 italic">{token}</span>;
          }
          if (['int', 'void', 'char', 'uint32_t', 'PPEB', 'HANDLE', 'BOOL', 'SIZE_T', 'DWORD', 'FARPROC', 'HMODULE'].includes(token)) {
            return <span key={tIdx} className="text-blue-700 font-bold">{token}</span>;
          }
          if (['if', 'else', 'while', 'for', 'return', 'break', 'continue', 'switch', 'case', 'default', 'true', 'false'].includes(token)) {
            return <span key={tIdx} className="text-purple-700 font-bold">{token}</span>;
          }
          if (token.startsWith('"') || token.startsWith("'")) {
            const rawStr = token.replace(/^["']|["']$/g, '');
            const renamed = isRenamed(rawStr) || isRenamed(token);
            return (
              <span
                key={tIdx}
                onClick={() => handleOpenRename(rawStr, 'string')}
                className={`text-amber-700 cursor-pointer hover:underline hover:bg-amber-50 rounded px-0.5 transition-colors ${
                  renamed ? 'font-bold bg-amber-100/70 border border-amber-300' : ''
                }`}
                title="Click to rename this string literal"
              >
                {token}
              </span>
            );
          }
          if (token.startsWith('0x') || /^\d+$/.test(token)) {
            return <span key={tIdx} className="text-rose-700">{token}</span>;
          }

          // Check if token contains identifiers
          // Split by punctuation so variables and function calls can be individually clicked
          const subTokens = token.split(/([a-zA-Z_][a-zA-Z0-9_]*)/g);
          return (
            <span key={tIdx}>
              {subTokens.map((sub, sIdx) => {
                if (!sub) return null;
                const isIdentifier = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(sub);
                if (isIdentifier) {
                  const renamed = isRenamed(sub);
                  const isFunc =
                    discoveredFunctions.includes(sub) ||
                    sub === activeFunctionName ||
                    sub.startsWith('loc_') ||
                    sub.startsWith('sub_');
                  return (
                    <span
                      key={sIdx}
                      onClick={() => handleOpenRename(sub, isFunc ? 'function' : 'variable')}
                      className={`cursor-pointer hover:underline hover:text-indigo-600 hover:bg-indigo-50/80 rounded px-0.5 transition-colors ${
                        renamed ? 'font-bold text-indigo-700 bg-indigo-50 border border-indigo-200' : ''
                      }`}
                      title={`Click to rename ${isFunc ? 'function' : 'variable'} "${sub}"`}
                    >
                      {sub}
                    </span>
                  );
                }
                return <span key={sIdx}>{sub}</span>;
              })}
            </span>
          );
        })}
      </>
    );
  };

  return (
    <div className="space-y-4">
      {/* Header & Controls Toolbar */}
      <div className="p-4 bg-white rounded-2xl border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shrink-0">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="text-sm font-bold text-slate-900 font-mono flex items-center gap-1.5">
                <span>Function:</span>
                <span className={isRenamed(decomp.function_name) ? 'text-indigo-700 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-200' : ''}>
                  {activeFunctionName}
                </span>
                <span className="text-slate-400 font-normal">({decomp.address})</span>
                <button
                  type="button"
                  onClick={() => handleOpenRename(activeFunctionName, 'function')}
                  className="p-1 text-slate-400 hover:text-indigo-600 hover:bg-slate-100 rounded transition-colors cursor-pointer"
                  title="Rename this function"
                >
                  <Edit3 className="w-3.5 h-3.5" />
                </button>
              </h4>
              {isRenamed(decomp.function_name) && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-amber-50 text-amber-700 border border-amber-200">
                  Renamed from {decomp.function_name}
                </span>
              )}
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-indigo-50 text-indigo-700 border border-indigo-200">
                Confidence: {decomp.confidence}%
              </span>
            </div>
            <p className="text-xs text-slate-500 font-mono truncate max-w-xl">
              {activeSignature}
            </p>
          </div>
        </div>

        {/* Action Controls & Mode Switcher */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Mode Switcher */}
          <div className="flex items-center bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs font-semibold">
            <button
              onClick={() => setViewMode('decompiler')}
              className={`px-3 py-1 rounded-lg transition-colors flex items-center gap-1.5 ${
                viewMode === 'decompiler'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>C/C++ Pseudocode</span>
            </button>
            <button
              onClick={() => setViewMode('side_by_side')}
              className={`px-3 py-1 rounded-lg transition-colors flex items-center gap-1.5 ${
                viewMode === 'side_by_side'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Split className="w-3.5 h-3.5" />
              <span>Split (Asm + C)</span>
            </button>
            <button
              onClick={() => setViewMode('assembly')}
              className={`px-3 py-1 rounded-lg transition-colors flex items-center gap-1.5 ${
                viewMode === 'assembly'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Table className="w-3.5 h-3.5" />
              <span>Assembly</span>
            </button>
            <button
              onClick={() => setViewMode('call_graph')}
              className={`px-3 py-1 rounded-lg transition-colors flex items-center gap-1.5 ${
                viewMode === 'call_graph'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <GitFork className="w-3.5 h-3.5 text-blue-600" />
              <span>Call Hierarchy Graph</span>
            </button>
            <button
              onClick={() => setViewMode('api_hashing')}
              className={`px-3 py-1 rounded-lg transition-colors flex items-center gap-1.5 ${
                viewMode === 'api_hashing'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Hash className="w-3.5 h-3.5 text-purple-600" />
              <span>API Hashing</span>
              {apiHashingMatches.length > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-purple-100 text-purple-800 font-mono">
                  {apiHashingMatches.length}
                </span>
              )}
            </button>
            <button
              onClick={() => setViewMode('flow_canvas')}
              className={`px-3 py-1 rounded-lg transition-colors flex items-center gap-1.5 ${
                viewMode === 'flow_canvas'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Network className="w-3.5 h-3.5 text-indigo-600" />
              <span>2D Flow Canvas</span>
            </button>
          </div>

          {/* XREFs Explorer Button */}
          <button
            onClick={() => handleOpenXrefs('ALL')}
            className="px-3 py-1.5 rounded-xl border border-blue-200 bg-blue-50/70 hover:bg-blue-100 text-blue-700 text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-2xs cursor-pointer"
            title="Inspect Cross-References (Callers, Jumps, Data References) across the binary"
          >
            <Layers className="w-3.5 h-3.5" />
            <span>XREFs</span>
            {xrefsData.total_xrefs > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-blue-600 text-white font-mono">
                {xrefsData.total_xrefs}
              </span>
            )}
          </button>

          {/* Rename Symbol Button */}
          <button
            onClick={() => handleOpenRename()}
            className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-2xs cursor-pointer ${
              renames.length > 0
                ? 'border-indigo-300 bg-indigo-50 text-indigo-700 hover:bg-indigo-100'
                : 'border-slate-200 bg-white hover:bg-slate-50 text-slate-700'
            }`}
            title="Rename Functions, Variables and Strings across all views"
          >
            <Edit3 className="w-3.5 h-3.5" />
            <span>Rename Symbol</span>
            {renames.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-indigo-600 text-white font-mono">
                {renames.length}
              </span>
            )}
          </button>

          {/* Copy Button */}
          <button
            onClick={handleCopyCode}
            className="px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-2xs"
            title="Copy C Code"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCode ? 'Copied' : 'Copy'}</span>
          </button>

          {/* Download .c File */}
          <button
            onClick={handleDownloadC}
            className="px-3 py-1.5 rounded-xl border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-2xs"
            title="Download .c File"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export .c</span>
          </button>
        </div>
      </div>

      {/* Feature Badges & Suspicious Constructs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold block mb-0.5">Control Flow</span>
          <div className="text-xs font-bold text-slate-800 flex items-center gap-1">
            <Layers className="w-3.5 h-3.5 text-indigo-600" />
            <span>{decomp.basic_blocks_count} Basic Blocks</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            {decomp.has_loops ? 'Loops Identified' : 'Linear Flow'}
          </span>
        </div>

        <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold block mb-0.5">Conditionals</span>
          <div className="text-xs font-bold text-slate-800 flex items-center gap-1">
            <Split className="w-3.5 h-3.5 text-amber-600" />
            <span>{decomp.has_conditionals ? 'Branches Reconstructed' : 'Direct Path'}</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">if / else structures</span>
        </div>

        <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold block mb-0.5">Resolved APIs</span>
          <div className="text-xs font-bold text-slate-800 flex items-center gap-1">
            <Terminal className="w-3.5 h-3.5 text-blue-600" />
            <span>{decomp.api_calls.length} External Calls</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono truncate block">
            {decomp.api_calls.join(', ') || 'Internal routines'}
          </span>
        </div>

        <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
          <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold block mb-0.5">Security Context</span>
          <div className="text-xs font-bold text-slate-800 flex items-center gap-1">
            {decomp.suspicious_constructs.length > 0 ? (
              <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
            ) : (
              <Sparkles className="w-3.5 h-3.5 text-emerald-600" />
            )}
            <span className={decomp.suspicious_constructs.length > 0 ? 'text-rose-700' : 'text-emerald-700'}>
              {decomp.suspicious_constructs.length > 0 ? `${decomp.suspicious_constructs.length} Evasion Patterns` : 'Standard Flow'}
            </span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono truncate block">
            {decomp.suspicious_constructs[0] || 'Clean semantics'}
          </span>
        </div>
      </div>

      {/* Main Code View Panels */}
      {viewMode === 'decompiler' && (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col font-mono text-xs">
          {/* Top Search / Filter */}
          <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-3">
            <span className="text-[11px] font-semibold text-slate-600 font-sans">
              High-Level C/C++ Representation ({lines.length} lines)
            </span>
            <div className="relative max-w-xs w-full">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search pseudocode..."
                className="w-full pl-8 pr-3 py-1 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder-slate-400 focus:outline-hidden focus:ring-1 focus:ring-indigo-500"
              />
            </div>
          </div>

          {/* Code Listing with Line Numbers */}
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto p-4 bg-slate-50/40">
            <div className="space-y-0.5 min-w-[700px]">
              {lines.map((line, idx) => (
                <div key={idx} className="flex items-start hover:bg-slate-100/70 rounded px-1 transition-colors">
                  <span className="w-10 shrink-0 text-slate-400 text-right pr-4 select-none font-mono text-[11px]">
                    {idx + 1}
                  </span>
                  <div className="flex-1 text-slate-900 leading-relaxed font-mono whitespace-pre text-[11px]">
                    {renderHighlightedLine(line, idx + 1)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Side-by-Side View: Assembly (Left) + C Decompiler (Right) */}
      {viewMode === 'side_by_side' && (
        <div className="space-y-3">
          {/* Synchronized Selection Indicator Banner & Control Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs shadow-2xs">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  selectedInstIndices.length > 0 || selectedCodeLines.length > 0
                    ? 'bg-indigo-600 animate-pulse'
                    : 'bg-slate-300'
                }`}
              />
              <span className="font-semibold text-slate-800">
                Synchronized Split Selection:
              </span>
              <span
                className={`font-mono px-2 py-0.5 rounded border text-[11px] font-bold ${
                  selectionSource === 'asm'
                    ? 'bg-indigo-100 border-indigo-300 text-indigo-900 ring-1 ring-indigo-200'
                    : selectedInstIndices.length > 0
                    ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                    : 'bg-white border-slate-200 text-slate-600'
                }`}
              >
                {selectedInstIndices.length} ASM instruction{selectedInstIndices.length === 1 ? '' : 's'}
                {selectionSource === 'asm' && ' (Source)'}
                {selectionSource === 'c' && selectedInstIndices.length > 0 && ' (Mapped)'}
              </span>
              <span className="text-slate-400">↔</span>
              <span
                className={`font-mono px-2 py-0.5 rounded border text-[11px] font-bold ${
                  selectionSource === 'c'
                    ? 'bg-indigo-100 border-indigo-300 text-indigo-900 ring-1 ring-indigo-200'
                    : selectedCodeLines.length > 0
                    ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                    : 'bg-white border-slate-200 text-slate-600'
                }`}
              >
                {selectedCodeLines.length} C statement{selectedCodeLines.length === 1 ? '' : 's'}
                {selectionSource === 'c' && ' (Source)'}
                {selectionSource === 'asm' && selectedCodeLines.length > 0 && ' (Mapped)'}
              </span>
              <span className="text-[10px] text-slate-500 font-sans ml-1 hidden xl:inline">
                • Drag to select multiple rows, hold Shift for range, or toggle Multi-Select mode
              </span>
            </div>

            <div className="flex items-center gap-2">
              {/* Multi-Select Mode Toggle */}
              <button
                type="button"
                onClick={() => setIsMultiSelectMode(!isMultiSelectMode)}
                className={`px-2.5 py-1 rounded-lg border text-xs font-mono font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs ${
                  isMultiSelectMode
                    ? 'bg-indigo-50 border-indigo-300 text-indigo-800 font-semibold'
                    : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
                }`}
                title={
                  isMultiSelectMode
                    ? 'Multi-Select Mode active (click rows to toggle)'
                    : 'Enable Multi-Select Mode to click multiple rows without modifier keys'
                }
              >
                {isMultiSelectMode ? (
                  <CheckSquare className="w-3.5 h-3.5 text-indigo-600" />
                ) : (
                  <Square className="w-3.5 h-3.5 text-slate-400" />
                )}
                <span>Multi-Select {isMultiSelectMode ? 'ON' : 'OFF'}</span>
              </button>

              {/* Quick Select All Buttons */}
              <button
                type="button"
                onClick={handleSelectAllAsm}
                className="px-2 py-1 rounded-lg bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100 text-xs font-mono transition-colors shadow-2xs cursor-pointer"
                title="Select all ASM instructions"
              >
                All ASM
              </button>

              <button
                type="button"
                onClick={handleSelectAllCode}
                className="px-2 py-1 rounded-lg bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100 text-xs font-mono transition-colors shadow-2xs cursor-pointer"
                title="Select all C pseudocode lines"
              >
                All C
              </button>

              {(selectedInstIndices.length > 0 || selectedCodeLines.length > 0) && (
                <button
                  type="button"
                  onClick={handleClearSelection}
                  className="px-2.5 py-1 rounded-lg bg-white border border-rose-200 text-rose-600 hover:text-rose-800 hover:bg-rose-50 text-xs font-mono transition-colors shadow-2xs cursor-pointer"
                  title="Clear current selection on both sides"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left: Disassembly */}
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col font-mono text-xs select-none">
              <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-semibold text-slate-700 font-sans">
                    Assembly Listing ({activeInstructions.length} insts)
                  </span>
                  {selectedInstIndices.length > 0 && (
                    <span
                      className={`px-1.5 py-0.2 rounded-full text-[10px] font-bold font-sans ${
                        selectionSource === 'asm'
                          ? 'bg-indigo-100 text-indigo-800'
                          : 'bg-emerald-100 text-emerald-800'
                      }`}
                    >
                      {selectedInstIndices.length} {selectionSource === 'asm' ? 'selected' : 'mapped'}
                    </span>
                  )}
                </div>
                <span className="text-[10px] font-mono text-indigo-600 font-bold">{decomp.address}</span>
              </div>
              <div ref={asmContainerRef} className="overflow-x-auto max-h-[550px] overflow-y-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-slate-100/80 text-[10px] uppercase text-slate-500 sticky top-0 border-b border-slate-200">
                    <tr>
                      <th className="py-2 px-3">Address</th>
                      <th className="py-2 px-3">Mnemonic</th>
                      <th className="py-2 px-3">Operands</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                    {activeInstructions.map((inst, idx) => {
                      const isSelected = selectedInstIndices.includes(idx);
                      const isPrimary = isSelected && selectionSource === 'asm';
                      const isMapped = isSelected && selectionSource === 'c';

                      return (
                        <tr
                          key={idx}
                          data-inst-idx={idx}
                          style={{ scrollMarginTop: '36px' }}
                          onClick={(e) => handleAsmRowClick(idx, e)}
                          onMouseDown={(e) => handleAsmRowMouseDown(idx, e)}
                          onMouseEnter={() => handleAsmRowMouseEnter(idx)}
                          className={`cursor-pointer transition-colors duration-150 select-none ${
                            isPrimary
                              ? 'bg-indigo-100/90 text-indigo-950 font-bold border-l-4 border-indigo-600 shadow-2xs'
                              : isMapped
                              ? 'bg-emerald-50 text-emerald-950 font-semibold border-l-4 border-emerald-500 shadow-2xs'
                              : 'hover:bg-slate-50'
                          }`}
                        >
                          <td className="py-1.5 px-3 text-slate-400 text-[10px] whitespace-nowrap">{inst.address}</td>
                          <td
                            className={`py-1.5 px-3 whitespace-nowrap ${
                              isPrimary
                                ? 'text-indigo-950 font-black'
                                : isMapped
                                ? 'text-emerald-900 font-bold'
                                : 'font-bold text-indigo-700'
                            }`}
                          >
                            {inst.mnemonic}
                          </td>
                          <td className="py-1.5 px-3 text-slate-800 flex items-center justify-between gap-2">
                            <span className="truncate">{inst.op_str}</span>
                            {isPrimary && (
                              <span className="px-1.5 py-0.2 rounded bg-indigo-200 text-indigo-900 text-[9px] font-bold font-sans shrink-0">
                                Selected
                              </span>
                            )}
                            {isMapped && (
                              <span className="px-1.5 py-0.2 rounded bg-emerald-100 text-emerald-800 text-[9px] font-bold font-sans shrink-0">
                                ↔ Mapped
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Right: Decompiler */}
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden flex flex-col font-mono text-xs select-none">
              <div className="px-4 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-semibold text-slate-700 font-sans">
                    C/C++ Pseudocode
                  </span>
                  {selectedCodeLines.length > 0 && (
                    <span
                      className={`px-1.5 py-0.2 rounded-full text-[10px] font-bold font-sans ${
                        selectionSource === 'c'
                          ? 'bg-indigo-100 text-indigo-800'
                          : 'bg-emerald-100 text-emerald-800'
                      }`}
                    >
                      {selectedCodeLines.length} {selectionSource === 'c' ? 'selected' : 'mapped'}
                    </span>
                  )}
                </div>
                <span className="text-[10px] font-mono text-emerald-700 font-bold">
                  Confidence {decomp.confidence}%
                </span>
              </div>
              <div ref={codeContainerRef} className="overflow-x-auto max-h-[550px] overflow-y-auto p-4 bg-slate-50/40">
                <div className="space-y-0.5">
                  {lines.map((line, idx) => {
                    const lineNum = idx + 1;
                    const isSelected = selectedCodeLines.includes(lineNum);
                    const isPrimary = isSelected && selectionSource === 'c';
                    const isMapped = isSelected && selectionSource === 'asm';

                    return (
                      <div
                        key={idx}
                        data-line-num={lineNum}
                        style={{ scrollMarginTop: '20px' }}
                        onClick={(e) => handleCodeLineClick(lineNum, e)}
                        onMouseDown={(e) => handleCodeLineMouseDown(lineNum, e)}
                        onMouseEnter={() => handleCodeLineMouseEnter(lineNum)}
                        className={`flex items-start rounded px-1.5 py-0.5 transition-colors duration-150 cursor-pointer select-none ${
                          isPrimary
                            ? 'bg-indigo-100/90 text-indigo-950 font-bold border-l-4 border-indigo-600 shadow-2xs'
                            : isMapped
                            ? 'bg-emerald-50 text-emerald-950 font-semibold border-l-4 border-emerald-500 shadow-2xs'
                            : 'hover:bg-slate-100/70'
                        }`}
                      >
                        <span
                          className={`w-8 shrink-0 text-right pr-3 select-none font-mono text-[10px] ${
                            isPrimary
                              ? 'text-indigo-700 font-bold'
                              : isMapped
                              ? 'text-emerald-600 font-bold'
                              : 'text-slate-400'
                          }`}
                        >
                          {lineNum}
                        </span>
                        <div className="flex-1 leading-relaxed font-mono whitespace-pre text-[11px] overflow-hidden text-ellipsis flex items-center justify-between">
                          <div>{renderHighlightedLine(line, lineNum)}</div>
                          {isPrimary && (
                            <span className="ml-2 px-1.5 py-0.2 rounded bg-indigo-200 text-indigo-900 text-[9px] font-bold font-sans shrink-0">
                              Selected
                            </span>
                          )}
                          {isMapped && (
                            <span className="ml-2 px-1.5 py-0.2 rounded bg-emerald-100 text-emerald-800 text-[9px] font-bold font-sans shrink-0">
                              ↔ Mapped
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Assembly Only View */}
      {viewMode === 'assembly' && (
        <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white font-mono text-xs shadow-sm">
          <div className="overflow-x-auto max-h-[550px] overflow-y-auto">
            <table className="w-full text-left text-slate-800">
              <thead className="bg-slate-100 text-slate-500 text-[11px] uppercase sticky top-0 border-b border-slate-200">
                <tr>
                  <th className="py-2.5 px-4 w-28">Address</th>
                  <th className="py-2.5 px-4 w-24">Mnemonic</th>
                  <th className="py-2.5 px-4">Operands</th>
                  <th className="py-2.5 px-4 w-24 text-center">XREFs</th>
                  <th className="py-2.5 px-4 w-36 text-right">Machine Hex</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {activeInstructions.map((inst: any, idx: number) => {
                  const xCount = lookupXrefsForSymbol(xrefsData, inst.address).length;
                  const opTarget = inst.op_str ? inst.op_str.replace(/[\[\]]/g, '').trim() : '';
                  const opXCount = opTarget ? lookupXrefsForSymbol(xrefsData, opTarget).length : 0;
                  return (
                    <tr key={idx} className="hover:bg-slate-50 font-mono">
                      <td className="py-1.5 px-4 text-indigo-600 font-bold">{inst.address}</td>
                      <td className="py-1.5 px-4 text-amber-700 font-bold">{inst.mnemonic}</td>
                      <td className="py-1.5 px-4 text-slate-700 flex items-center justify-between">
                        <span>{inst.op_str}</span>
                        {opXCount > 0 && (
                          <button
                            onClick={() => handleOpenXrefs(opTarget)}
                            className="px-1.5 py-0.2 rounded text-[10px] bg-blue-50 text-blue-700 hover:bg-blue-100 border border-blue-200"
                            title={`Inspect XREFs for ${opTarget}`}
                          >
                            XREF ({opXCount})
                          </button>
                        )}
                      </td>
                      <td className="py-1.5 px-4 text-center">
                        {xCount > 0 && (
                          <button
                            onClick={() => handleOpenXrefs(inst.address)}
                            className="px-1.5 py-0.2 rounded text-[10px] bg-indigo-50 text-indigo-700 hover:bg-indigo-100 border border-indigo-200"
                            title={`View ${xCount} cross-references pointing to ${inst.address}`}
                          >
                            {xCount}
                          </button>
                        )}
                      </td>
                      <td className="py-1.5 px-4 text-right text-slate-400 text-[10px] tracking-widest">{inst.bytes}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Function Call Hierarchy Graph View */}
      {viewMode === 'call_graph' && (
        <div className="h-[650px]">
          <FunctionCallGraphView
            callGraphData={callGraphData}
            onOpenXrefs={handleOpenXrefs}
            onJumpToAddress={handleJumpToAddress}
          />
        </div>
      )}

      {/* API Hashing & Dynamic Resolution View */}
      {viewMode === 'api_hashing' && (
        <div className="h-[650px]">
          <ApiHashingInspectorView
            matches={apiHashingMatches}
            filename={filename}
            onOpenXrefs={handleOpenXrefs}
            onJumpToAddress={handleJumpToAddress}
          />
        </div>
      )}

      {/* 3D Isometric & 2D Control Flow Graph Flow Canvas */}
      {viewMode === 'flow_canvas' && (
        <div className="h-[680px]">
          <SingleBinaryFlowCanvas
            blocks={singleCfgData.blocks}
            edges={singleCfgData.edges}
            binaryName={filename || binaryInfo.architecture || 'Target Binary'}
            onOpenXrefs={handleOpenXrefs}
            onJumpToAddress={handleJumpToAddress}
          />
        </div>
      )}

      {/* Cross-References (XREFs) Modal */}
      <XrefsModal
        isOpen={isXrefsModalOpen}
        onClose={() => setIsXrefsModalOpen(false)}
        initialSymbol={xrefsTargetSymbol}
        xrefsData={xrefsData}
        onJumpToAddress={handleJumpToAddress}
      />

      {/* Symbol Rename Modal */}
      <SymbolRenameModal
        isOpen={isRenameModalOpen}
        onClose={() => setIsRenameModalOpen(false)}
        initialOriginal={renameTargetSymbol}
        initialCategory={renameTargetCategory}
        discoveredFunctions={discoveredFunctions}
        discoveredVariables={discoveredVariables}
        discoveredStrings={discoveredStrings}
      />
    </div>
  );
};
