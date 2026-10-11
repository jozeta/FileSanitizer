import React, { useState, useMemo } from 'react';
import {
  Cpu,
  Layers,
  FileCode,
  Download,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FolderTree,
  Terminal,
  Boxes,
  Activity,
  Compass,
  FileCheck,
  Edit3
} from 'lucide-react';
import { formatBytes } from '../utils/formatters';
import { BinaryInfo, AntiAnalysisInfo } from '../types';
import { apiClient } from '../api/client';
import { BinaryDecompilerCard } from './BinaryDecompilerCard';
import { AntiAnalysisInspectorCard } from './AntiAnalysisInspectorCard';
import { useSymbolRenames, SymbolCategory } from '../context/SymbolRenameContext';
import { SymbolRenameModal } from './SymbolRenameModal';
import { ReferencedText } from './ReferencedFileLink';

interface BinaryTriageCardProps {
  jobId: string;
  binaryInfo?: BinaryInfo;
  filename?: string;
  findings?: Array<{ category: string; severity: string; title: string; description: string; details?: any }>;
  antiAnalysis?: AntiAnalysisInfo;
  workspaceJobs?: any[];
  onSelectJob?: (newJobId: string) => void;
}

export const BinaryTriageCard: React.FC<BinaryTriageCardProps> = ({
  jobId,
  binaryInfo,
  filename: _filename,
  findings: _findings = [],
  antiAnalysis,
  workspaceJobs,
  onSelectJob,
}) => {
  const isShellcodeFile = Boolean(
    (binaryInfo as any)?.shellcode?.is_shellcode ||
    binaryInfo?.format?.toLowerCase().includes('shellcode')
  );
  const [activeTab, setActiveTab] = useState<'headers' | 'sections' | 'imports' | 'exports' | 'resources' | 'strings' | 'compilers' | 'disassembly' | 'decompiler' | 'anti_analysis' | 'authenticode' | 'mitigations' | 'shellcode'>(
    isShellcodeFile ? 'shellcode' : 'headers'
  );
  const [selectedDll, setSelectedDll] = useState<string>('all');
  const [importSearch, setImportSearch] = useState('');
  const [stringSearch, setStringSearch] = useState('');
  const [stringCategory, setStringCategory] = useState<'all' | 'network' | 'file_paths' | 'registry' | 'commands'>('all');
  const [minStrLength, setMinStrLength] = useState<string>('5');
  const [maxStrLength, setMaxStrLength] = useState<string>('');
  const [copiedImphash, setCopiedImphash] = useState(false);
  const [copiedRichHeader, setCopiedRichHeader] = useState(false);

  const { getRenamed, applyToInstruction, renames } = useSymbolRenames();
  const [isRenameModalOpen, setIsRenameModalOpen] = useState(false);
  const [renameTargetSymbol, setRenameTargetSymbol] = useState('');
  const [renameTargetCategory, setRenameTargetCategory] = useState<SymbolCategory>('function');

  const handleOpenRename = (symbol: string = '', cat: SymbolCategory = 'function') => {
    setRenameTargetSymbol(symbol);
    setRenameTargetCategory(cat);
    setIsRenameModalOpen(true);
  };

  const discoveredFunctions = useMemo(() => {
    const set = new Set<string>();
    const insts = (binaryInfo as any)?.disassembly?.instructions || [];
    insts.forEach((inst: any) => {
      if (inst.mnemonic?.startsWith('j') || inst.mnemonic === 'call') {
        if (inst.op_str && /^(loc_|sub_|0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*)/.test(inst.op_str)) {
          set.add(inst.op_str);
        }
      }
    });
    if (binaryInfo?.entry_point) set.add(binaryInfo.entry_point);
    return Array.from(set);
  }, [binaryInfo]);

  const discoveredVariables = useMemo(() => {
    const set = new Set<string>();
    const insts = (binaryInfo as any)?.disassembly?.instructions || [];
    insts.forEach((inst: any) => {
      if (inst?.op_str) {
        const matches = inst.op_str.match(/\b(var_\w+|arg_\w+|[re]?[abcd]x|[re]?[si]p|[re]?[sb]p|r\d+)\b/g);
        if (matches) matches.forEach((m: string) => set.add(m));
      }
    });
    return Array.from(set);
  }, [binaryInfo]);

  const discoveredStrings = useMemo(() => {
    const set = new Set<string>();
    if (binaryInfo?.strings) {
      const all = Array.isArray(binaryInfo.strings.all_sample) ? binaryInfo.strings.all_sample : [];
      all.slice(0, 50).forEach((s: any) => {
        const val = typeof s === 'string' ? s : s.value;
        if (val && val.length > 2 && val.length < 60) set.add(val);
      });
    }
    return Array.from(set);
  }, [binaryInfo]);

  if (!binaryInfo || typeof binaryInfo !== 'object') {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Cpu className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No executable binary data available for this file.</p>
      </div>
    );
  }

  // Format indicators
  const isPE = Boolean(
    (binaryInfo.format && binaryInfo.format.toUpperCase().includes('PE')) ||
    (binaryInfo.dos_header && Object.keys(binaryInfo.dos_header).length > 0) ||
    Boolean(binaryInfo.optional_header)
  );
  const isELF = Boolean(binaryInfo.format && binaryInfo.format.toUpperCase().includes('ELF'));
  const isMachO = Boolean(binaryInfo.format && binaryInfo.format.toUpperCase().includes('MACH-O'));

  // Digital Signature Check
  const hasAuthenticode = Boolean(
    typeof binaryInfo.digital_signature === 'string' &&
    binaryInfo.digital_signature.toUpperCase().includes('SIGNED') &&
    !binaryInfo.digital_signature.toUpperCase().includes('UNSIGNED')
  );

  // Packer & Protection Detection
  const packersList = useMemo(() => {
    if (Array.isArray(binaryInfo.packers) && binaryInfo.packers.length > 0) {
      return binaryInfo.packers.filter((p) => typeof p === 'string' && p.trim().length > 0);
    }
    const directPackers = (binaryInfo as any).packers;
    if (typeof directPackers === 'string' && directPackers.trim().length > 0) {
      return [directPackers];
    }
    const pcPacker = binaryInfo.packers_and_compilers?.packer;
    if (typeof pcPacker === 'string' && pcPacker.trim().length > 0) {
      return [pcPacker];
    }
    return [];
  }, [binaryInfo.packers, (binaryInfo as any).packers, binaryInfo.packers_and_compilers]);

  const isPacked = Boolean(
    binaryInfo.is_packed ||
    binaryInfo.packers_and_compilers?.is_packed ||
    packersList.length > 0
  );

  // Compilers & Toolchains Detection
  const compilersList = useMemo(() => {
    if (Array.isArray(binaryInfo.compilers) && binaryInfo.compilers.length > 0) {
      return binaryInfo.compilers.filter((c) => typeof c === 'string' && c.trim().length > 0);
    }
    const directComp = (binaryInfo as any).compiler;
    if (typeof directComp === 'string' && directComp && directComp !== 'Unknown') {
      return [directComp];
    }
    const pcComp = binaryInfo.packers_and_compilers?.compiler;
    if (typeof pcComp === 'string' && pcComp && pcComp !== 'Unknown') {
      return [pcComp];
    }
    return [];
  }, [binaryInfo.compilers, (binaryInfo as any).compiler, binaryInfo.packers_and_compilers]);

  // Detected Tools (Rich Header)
  const detectedTools = useMemo(() => {
    if (Array.isArray(binaryInfo.detected_tools) && binaryInfo.detected_tools.length > 0) {
      return binaryInfo.detected_tools;
    }
    const richTools = (binaryInfo as any).rich_header?.tools;
    if (Array.isArray(richTools) && richTools.length > 0) {
      return richTools.map((t: any) => ({
        tool_id: String(t.tool_id ?? ''),
        name: `Tool ID ${t.tool_id ?? ''} (Build ${t.build_id ?? ''})`,
        count: t.times_used ?? t.count ?? 1,
        compiler: `MSVC Build ${t.build_id ?? ''}`
      }));
    }
    return [];
  }, [binaryInfo.detected_tools, (binaryInfo as any).rich_header]);

  // Filtered imports
  const dllNames = useMemo(() => {
    if (!binaryInfo.imports || typeof binaryInfo.imports !== 'object') return [];
    return Object.keys(binaryInfo.imports);
  }, [binaryInfo.imports]);

  const filteredImports = useMemo(() => {
    if (!binaryInfo.imports || typeof binaryInfo.imports !== 'object') return [];
    let list: Array<{
      dll: string;
      name: string;
      ordinal?: number;
      address?: string;
      is_suspicious: boolean;
      severity?: string;
      description?: string;
    }> = [];

    const dllsToInspect = selectedDll === 'all' ? dllNames : [selectedDll];
    for (const d of dllsToInspect) {
      const funcs = binaryInfo.imports[d];
      if (!Array.isArray(funcs)) continue;
      for (const fn of funcs) {
        let fnName = '';
        let fnOrdinal: number | undefined;
        let fnAddress = '0x0';
        let fnSuspicious = false;
        let fnSeverity: string | undefined;
        let fnDesc = '';

        if (typeof fn === 'string') {
          fnName = fn;
        } else if (fn && typeof fn === 'object') {
          fnName = fn.name || '';
          fnOrdinal = fn.ordinal;
          fnAddress = fn.address || '0x0';
          fnSuspicious = Boolean(fn.is_suspicious);
          fnSeverity = fn.severity;
          fnDesc = fn.description || '';
        }

        const query = importSearch.toLowerCase();
        if (!query || fnName.toLowerCase().includes(query) || d.toLowerCase().includes(query)) {
          list.push({
            dll: d,
            name: fnName,
            ordinal: fnOrdinal,
            address: fnAddress,
            is_suspicious: fnSuspicious,
            severity: fnSeverity,
            description: fnDesc
          });
        }
      }
    }
    return list;
  }, [binaryInfo.imports, selectedDll, importSearch, dllNames]);

  // Filtered strings
  const filteredStrings = useMemo(() => {
    if (!binaryInfo.strings || typeof binaryInfo.strings !== 'object') return [];
    let pool: string[] = [];
    if (stringCategory === 'network') pool = Array.isArray(binaryInfo.strings.network) ? binaryInfo.strings.network : [];
    else if (stringCategory === 'file_paths') pool = Array.isArray(binaryInfo.strings.file_paths) ? binaryInfo.strings.file_paths : [];
    else if (stringCategory === 'registry') pool = Array.isArray(binaryInfo.strings.registry) ? binaryInfo.strings.registry : [];
    else if (stringCategory === 'commands') pool = Array.isArray(binaryInfo.strings.commands) ? binaryInfo.strings.commands : [];
    else pool = Array.isArray(binaryInfo.strings.all_sample) ? binaryInfo.strings.all_sample : [];

    const query = stringSearch.toLowerCase();
    const minLen = minStrLength ? parseInt(minStrLength, 10) : 0;
    const maxLen = maxStrLength ? parseInt(maxStrLength, 10) : Infinity;

    return pool.filter((s) => {
      if (typeof s !== 'string') return false;
      const len = s.length;
      if (!isNaN(minLen) && minLen > 0 && len < minLen) return false;
      if (!isNaN(maxLen) && isFinite(maxLen) && len > maxLen) return false;
      if (query && !s.toLowerCase().includes(query)) return false;
      return true;
    });
  }, [binaryInfo.strings, stringCategory, stringSearch, minStrLength, maxStrLength]);

  // Characteristics flags for File Header
  const fileHeaderCharFlags: string[] = useMemo(() => {
    if (!binaryInfo.file_header) return [];
    if (Array.isArray(binaryInfo.file_header.characteristics)) {
      return binaryInfo.file_header.characteristics;
    }
    if (Array.isArray((binaryInfo.file_header as any).characteristics_flags)) {
      return (binaryInfo.file_header as any).characteristics_flags;
    }
    return [];
  }, [binaryInfo.file_header]);

  const fileHeaderCharHex = binaryInfo.file_header
    ? binaryInfo.file_header.characteristics_hex ||
      (typeof binaryInfo.file_header.characteristics === 'string' ? binaryInfo.file_header.characteristics : '0x0')
    : '0x0';

  const hasDosHeader = Boolean(binaryInfo.dos_header && Object.keys(binaryInfo.dos_header).length > 0);
  const hasFileHeader = Boolean(binaryInfo.file_header && Object.keys(binaryInfo.file_header).length > 0);
  const hasOptHeader = Boolean(binaryInfo.optional_header && Object.keys(binaryInfo.optional_header).length > 0);

  const sectionsCount = binaryInfo.sections_count || (Array.isArray(binaryInfo.sections) ? binaryInfo.sections.length : 0);
  const resourcesCount = Array.isArray(binaryInfo.resources) ? binaryInfo.resources.length : 0;
  const exportsCount = Array.isArray(binaryInfo.exports) ? binaryInfo.exports.length : 0;
  const suspiciousApisCount = Array.isArray(binaryInfo.suspicious_apis) ? binaryInfo.suspicious_apis.length : 0;
  const abnormalResCount = Array.isArray(binaryInfo.abnormal_resources) ? binaryInfo.abnormal_resources.length : 0;

  // Entropy chart renderer — pure SVG, no dependencies
  const EntropyChart = ({ sections, overallEntropy }: { sections: any[]; overallEntropy?: number }) => {
    const validSecs = sections.filter(s => typeof s.entropy === 'number' && s.name);
    if (validSecs.length === 0) return null;

    const chartW = 600;
    const chartH = 200;
    const padL = 48;
    const padR = 16;
    const padT = 16;
    const padB = 52;
    const innerW = chartW - padL - padR;
    const innerH = chartH - padT - padB;
    const maxEntropy = 8.0;
    const barW = Math.max(8, Math.min(60, Math.floor(innerW / validSecs.length) - 4));

    const entropyColor = (e: number) =>
      e >= 7.2 ? '#ef4444' :   // red: packed/encrypted
      e >= 6.5 ? '#f97316' :   // orange: high
      e >= 5.0 ? '#f59e0b' :   // amber: moderate
      '#22c55e';               // green: low

    const yForEntropy = (e: number) => padT + innerH - (e / maxEntropy) * innerH;
    const packedLineY = yForEntropy(7.2);

    return (
      <div className="w-full">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
            <span>📊</span> Section Entropy Analysis
            <span className="text-[10px] text-slate-400 font-normal">(binwalk-style)</span>
          </span>
          {typeof overallEntropy === 'number' && (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-lg border ${
              overallEntropy >= 7.2 ? 'bg-red-50 text-red-700 border-red-200' :
              overallEntropy >= 6.5 ? 'bg-orange-50 text-orange-700 border-orange-200' :
              overallEntropy >= 5.0 ? 'bg-amber-50 text-amber-700 border-amber-200' :
              'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              Overall: {overallEntropy.toFixed(3)} / 8.0
            </span>
          )}
        </div>
        <div className="overflow-x-auto">
          <svg
            viewBox={`0 0 ${chartW} ${chartH}`}
            className="w-full h-auto"
            style={{ minWidth: `${Math.max(300, validSecs.length * 40)}px`, maxHeight: '220px' }}
          >
            {/* Y-axis gridlines */}
            {[0, 2, 4, 6, 8].map(v => {
              const y = yForEntropy(v);
              return (
                <g key={v}>
                  <line x1={padL} y1={y} x2={chartW - padR} y2={y} stroke="#e2e8f0" strokeWidth="1" strokeDasharray={v === 0 ? '0' : '4 2'} />
                  <text x={padL - 6} y={y + 4} textAnchor="end" fontSize="9" fill="#94a3b8" fontFamily="monospace">{v}</text>
                </g>
              );
            })}

            {/* Packed threshold line at 7.2 */}
            <line x1={padL} y1={packedLineY} x2={chartW - padR} y2={packedLineY}
              stroke="#ef4444" strokeWidth="1.5" strokeDasharray="6 3" opacity="0.7" />
            <text x={chartW - padR - 2} y={packedLineY - 4} textAnchor="end" fontSize="9" fill="#ef4444" fontFamily="monospace">7.2 packed</text>

            {/* Bars */}
            {validSecs.map((sec, i) => {
              const slotW = innerW / validSecs.length;
              const x = padL + i * slotW + (slotW - barW) / 2;
              const barH = (sec.entropy / maxEntropy) * innerH;
              const y = padT + innerH - barH;
              const color = entropyColor(sec.entropy);
              const label = sec.name.length > 8 ? sec.name.slice(0, 7) + '…' : sec.name;
              return (
                <g key={i}>
                  <rect x={x} y={y} width={barW} height={Math.max(2, barH)}
                    fill={color} opacity="0.85" rx="3"
                    className="transition-opacity hover:opacity-100"
                  >
                    <title>{sec.name}{'\n'}Entropy: {sec.entropy.toFixed(3)} / 8.0{'\n'}Size: {(sec.raw_size || sec.size || 0).toLocaleString()} bytes{sec.is_packed ? '\n⚠ HIGH ENTROPY — possibly packed/encrypted' : ''}</title>
                  </rect>
                  {/* entropy value label on bar */}
                  {barH > 20 && (
                    <text x={x + barW / 2} y={y + 13} textAnchor="middle" fontSize="8" fill="white" fontFamily="monospace" fontWeight="bold">
                      {sec.entropy.toFixed(1)}
                    </text>
                  )}
                  {/* section name below */}
                  <text
                    x={x + barW / 2}
                    y={chartH - padB + 16}
                    textAnchor="middle"
                    fontSize="9"
                    fill="#64748b"
                    fontFamily="monospace"
                    transform={`rotate(-35, ${x + barW / 2}, ${chartH - padB + 16})`}
                  >
                    {label}
                  </text>
                </g>
              );
            })}

            {/* Y-axis label */}
            <text
              x={10}
              y={padT + innerH / 2}
              textAnchor="middle"
              fontSize="9"
              fill="#94a3b8"
              fontFamily="monospace"
              transform={`rotate(-90, 10, ${padT + innerH / 2})`}
            >
              Entropy (0–8)
            </text>
          </svg>
        </div>
        {/* Legend */}
        <div className="flex items-center gap-4 mt-2 text-[10px] font-medium">
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-emerald-500 inline-block"></span> Low (0–5)</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-amber-400 inline-block"></span> Moderate (5–6.5)</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-orange-500 inline-block"></span> High (6.5–7.2)</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500 inline-block"></span> Packed/Encrypted (≥7.2)</span>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-100 mb-5 gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-50 text-blue-600 rounded-2xl border border-blue-100 text-lg">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                PE & Binary Static Inspection (PE-bear / DIE Triage)
              </h3>
              <p className="text-xs text-slate-500">
                Headers, section entropy, dangerous Win32 APIs, resource payloads, compilers & section dumps.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="px-3 py-1 bg-slate-100 text-slate-800 border border-slate-200 rounded-full text-xs font-mono font-bold">
              {binaryInfo.format || 'Binary'} ({binaryInfo.architecture || 'Unknown Arch'})
            </span>

            {isPacked ? (
              <span className="px-3 py-1 bg-rose-50 text-rose-800 border border-rose-200 rounded-full text-xs font-bold flex items-center gap-1.5 animate-pulse">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                Packed / Protected: {packersList.join(', ') || 'High Entropy'}
              </span>
            ) : (
              <span className="px-3 py-1 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                Non-Packed Binary
              </span>
            )}

            {hasAuthenticode ? (
              <span className="px-3 py-1 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                Signed Binary
              </span>
            ) : (
              <span className="px-3 py-1 bg-slate-100 text-slate-600 border border-slate-200 rounded-full text-xs font-medium">
                {typeof binaryInfo.digital_signature === 'string' && binaryInfo.digital_signature.includes('UNSIGNED')
                  ? 'Unsigned Binary'
                  : binaryInfo.digital_signature || 'Unsigned Binary'}
              </span>
            )}
          </div>
        </div>

        {/* Top Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs mb-4">
          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Subsystem
            </span>
            <span className="text-slate-900 font-bold truncate block">{binaryInfo.subsystem || 'Unknown'}</span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Entry Point
            </span>
            <span className="text-slate-900 font-mono font-bold truncate block">
              {binaryInfo.optional_header?.address_of_entry_point || binaryInfo.entry_point || '0x0'}
            </span>
            <span className="text-[10px] text-slate-400 truncate block">
              in {binaryInfo.optional_header?.entry_point_section || 'Section'}
            </span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Sections
            </span>
            <span className="text-slate-900 font-bold">{sectionsCount} sections</span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Imports
            </span>
            <span className="text-slate-900 font-bold">
              {binaryInfo.total_imports_count || 0} APIs ({binaryInfo.import_libraries_count || dllNames.length} DLLs)
            </span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Resources
            </span>
            <span className="text-slate-900 font-bold">
              {resourcesCount} items ({binaryInfo.resource_types_count || 0} types)
            </span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Overlay / Slack
            </span>
            <span
              className={`font-bold ${
                binaryInfo.size_analysis?.has_overlay ? 'text-amber-700' : 'text-slate-900'
              }`}
            >
              {binaryInfo.size_analysis?.has_overlay
                ? formatBytes(binaryInfo.size_analysis.overlay_size || 0)
                : 'None'}
            </span>
          </div>

          {binaryInfo.imphash && (
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
                Imphash
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(binaryInfo.imphash || '');
                  setCopiedImphash(true);
                  setTimeout(() => setCopiedImphash(false), 2000);
                }}
                className="text-indigo-600 hover:text-indigo-800 font-mono text-xs font-bold truncate block w-full text-left cursor-pointer"
                title={`Click to copy: ${binaryInfo.imphash}`}
              >
                {copiedImphash ? '✓ Copied' : binaryInfo.imphash}
              </button>
            </div>
          )}

          {(binaryInfo as any).rich_header?.md5 && (
            <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
                Rich Header MD5
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText((binaryInfo as any).rich_header?.md5 || '');
                  setCopiedRichHeader(true);
                  setTimeout(() => setCopiedRichHeader(false), 2000);
                }}
                className="text-indigo-600 hover:text-indigo-800 font-mono text-xs font-bold truncate block w-full text-left cursor-pointer"
                title={`Click to copy: ${(binaryInfo as any).rich_header?.md5}`}
              >
                {copiedRichHeader ? '✓ Copied' : (binaryInfo as any).rich_header.md5}
              </button>
            </div>
          )}
        </div>

        {/* Tab Controls */}
        <div className="flex border-b border-slate-200 gap-1 overflow-x-auto pt-2">
          <button
            onClick={() => setActiveTab('headers')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'headers'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{isPE ? 'MZ & PE Headers' : isELF ? 'ELF Structure' : isMachO ? 'Mach-O Header' : 'Headers'}</span>
          </button>

          <button
            onClick={() => setActiveTab('sections')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'sections'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Boxes className="w-3.5 h-3.5" />
            <span>Sections & Dumps ({sectionsCount})</span>
          </button>

          <button
            onClick={() => setActiveTab('imports')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'imports'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FolderTree className="w-3.5 h-3.5" />
            <span>Imports & Libraries ({binaryInfo.total_imports_count || 0})</span>
            {suspiciousApisCount > 0 && (
              <span className="px-1.5 py-0.5 bg-rose-100 text-rose-800 rounded-full text-[10px] font-bold">
                {suspiciousApisCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('exports')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'exports'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Exports ({exportsCount})</span>
          </button>

          <button
            onClick={() => setActiveTab('resources')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'resources'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Compass className="w-3.5 h-3.5" />
            <span>Resources & Payloads ({resourcesCount})</span>
            {abnormalResCount > 0 && (
              <span className="px-1.5 py-0.5 bg-amber-100 text-amber-800 rounded-full text-[10px] font-bold">
                {abnormalResCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('strings')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'strings'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>String Search ({binaryInfo.strings?.total_count || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('compilers')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'compilers'
                ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Compilers & Protectors</span>
          </button>

          {(binaryInfo as any).disassembly?.instructions?.length > 0 && (
            <button
              onClick={() => setActiveTab('disassembly')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'disassembly'
                  ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Capstone EP Disassembly</span>
              {(binaryInfo as any).disassembly?.suspicious_patterns?.length > 0 && (
                <span className="px-1.5 py-0.5 bg-rose-100 text-rose-800 rounded-full text-[10px] font-bold">
                  {(binaryInfo as any).disassembly.suspicious_patterns.length}
                </span>
              )}
            </button>
          )}

          {Boolean((binaryInfo as any).decompilation || (binaryInfo as any).disassembly?.instructions?.length > 0) && (
            <button
              onClick={() => setActiveTab('decompiler')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'decompiler'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <FileCode className="w-3.5 h-3.5 text-indigo-600" />
              <span>C/C++ Decompiler</span>
              <span className="px-1.5 py-0.5 bg-indigo-100 text-indigo-800 rounded-full text-[10px] font-bold">
                C-Code
              </span>
            </button>
          )}

          {((binaryInfo as any)?.anti_analysis || antiAnalysis) && (
            <button
              onClick={() => setActiveTab('anti_analysis')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'anti_analysis'
                  ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Anti-Analysis & Evasion</span>
              {Boolean(antiAnalysis?.techniques && antiAnalysis.techniques.length > 0) && (
                <span className="px-1.5 py-0.2 bg-rose-500 text-white rounded-full text-[10px] font-bold">
                  {antiAnalysis?.techniques.length}
                </span>
              )}
            </button>
          )}

          {(binaryInfo as any).authenticode && (
            <button
              onClick={() => setActiveTab('authenticode')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'authenticode'
                  ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <FileCheck className="w-3.5 h-3.5" />
              <span>Authenticode Signatures</span>
            </button>
          )}

          {Boolean((binaryInfo as any).elf_mitigations || (binaryInfo as any).pe_mitigations || (binaryInfo as any).mitigations) && (
            <button
              onClick={() => setActiveTab('mitigations')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'mitigations'
                  ? 'bg-blue-50/80 text-blue-700 border-b-2 border-blue-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{isPE ? 'PE Exploit Mitigations' : isELF ? 'ELF Mitigations' : 'Exploit Mitigations'}</span>
            </button>
          )}

          {((binaryInfo as any).shellcode || isShellcodeFile) && (
            <button
              onClick={() => setActiveTab('shellcode')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'shellcode'
                  ? 'bg-rose-50/80 text-rose-700 border-b-2 border-rose-600 font-bold'
                  : 'text-rose-600 hover:text-rose-900 hover:bg-rose-50'
              }`}
            >
              <Cpu className="w-3.5 h-3.5 text-rose-600" />
              <span>Shellcode Forensics</span>
              {Boolean((binaryInfo as any).shellcode?.detected_features?.length) && (
                <span className="px-1.5 py-0.5 bg-rose-200 text-rose-800 rounded-full text-[10px] font-bold">
                  {(binaryInfo as any).shellcode.detected_features.length}
                </span>
              )}
            </button>
          )}
        </div>

        {/* Tab 1: Headers & Overview */}
        {activeTab === 'headers' && (
          <div className="pt-4 space-y-5">
            {/* DOS / MZ Header */}
            {hasDosHeader && binaryInfo.dos_header && (
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-bold text-xs text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-blue-600" />
                    <span>DOS / MZ Header (IMAGE_DOS_HEADER)</span>
                  </h4>
                  <span className="text-[11px] font-mono text-slate-500">
                    Stub Size: {binaryInfo.dos_stub?.size_bytes || 0} bytes
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono mb-3">
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">e_magic</span>
                    <span className="text-slate-900 font-bold">{binaryInfo.dos_header.e_magic || '0x5a4d (MZ)'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">e_lfanew (PE Offset)</span>
                    <span className="text-indigo-600 font-bold">{binaryInfo.dos_header.e_lfanew || '0x0'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">e_cblp</span>
                    <span className="text-slate-800">{binaryInfo.dos_header.e_cblp || '0x0'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">e_cp</span>
                    <span className="text-slate-800">{binaryInfo.dos_header.e_cp || '0x0'}</span>
                  </div>
                </div>

                {binaryInfo.dos_stub?.stub_message && (
                  <div className="text-[11px] text-slate-600 bg-white p-2.5 rounded-xl border border-slate-200 font-mono">
                    <span className="text-slate-400 block text-[10px] uppercase font-sans font-semibold">
                      DOS Stub String
                    </span>
                    {binaryInfo.dos_stub.stub_message}
                  </div>
                )}
              </div>
            )}

            {/* PE File Header (COFF) */}
            {hasFileHeader && binaryInfo.file_header && (
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-3">
                <h4 className="font-bold text-xs text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-indigo-600" />
                  <span>PE COFF File Header (IMAGE_FILE_HEADER)</span>
                </h4>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Machine Architecture</span>
                    <span className="text-slate-900 font-bold">{binaryInfo.file_header.machine || 'Unknown'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Number of Sections</span>
                    <span className="text-slate-900 font-bold">{binaryInfo.file_header.number_of_sections || 0}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">TimeDateStamp</span>
                    <span className="text-slate-800 text-[11px]">
                      {binaryInfo.file_header.timestamp || (binaryInfo.file_header as any).compile_time || 'Unknown'}
                    </span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Characteristics</span>
                    <span className="text-slate-800 font-bold">{fileHeaderCharHex}</span>
                  </div>
                </div>

                {fileHeaderCharFlags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {fileHeaderCharFlags.map((c, i) => (
                      <span key={i} className="px-2 py-0.5 bg-slate-200 text-slate-700 rounded text-[10px] font-mono">
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Optional Header */}
            {hasOptHeader && binaryInfo.optional_header && (
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-3">
                <h4 className="font-bold text-xs text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-purple-600" />
                  <span>PE Optional Header (IMAGE_OPTIONAL_HEADER)</span>
                </h4>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Magic (Format)</span>
                    <span className="text-slate-900 font-bold">{binaryInfo.optional_header.magic || 'PE32'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Address of Entry Point</span>
                    <span className="text-indigo-600 font-bold">
                      {binaryInfo.optional_header.address_of_entry_point || '0x0'}
                    </span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Image Base</span>
                    <span className="text-slate-800">{binaryInfo.optional_header.image_base || '0x0'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Linker Version</span>
                    <span className="text-slate-800">{binaryInfo.optional_header.linker_version || 'Unknown'}</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Size of Image (Virtual)</span>
                    <span className="text-slate-800">
                      {formatBytes(binaryInfo.optional_header.size_of_image || 0)}
                    </span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Size of Headers</span>
                    <span className="text-slate-800">{binaryInfo.optional_header.size_of_headers || 0} bytes</span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Checksum</span>
                    <span
                      className={`font-bold ${
                        binaryInfo.optional_header.checksum_verified ? 'text-emerald-700' : 'text-rose-700'
                      }`}
                    >
                      {binaryInfo.optional_header.checksum || '0x0'}{' '}
                      {binaryInfo.optional_header.checksum_verified ? '✓' : '(Mismatch)'}
                    </span>
                  </div>
                  <div className="p-2 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Subsystem</span>
                    <span className="text-slate-800">{binaryInfo.optional_header.subsystem || 'Unknown'}</span>
                  </div>
                </div>

                {/* DllCharacteristics flags */}
                {Array.isArray(binaryInfo.optional_header.dll_characteristics_flags) &&
                  binaryInfo.optional_header.dll_characteristics_flags.length > 0 && (
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase font-sans font-semibold block mb-1">
                        Security Mitigations & Flags (DllCharacteristics)
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {binaryInfo.optional_header.dll_characteristics_flags.map((flag, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 bg-blue-50 text-blue-800 border border-blue-200 rounded text-[10px] font-mono font-medium"
                          >
                            {flag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
              </div>
            )}

            {/* Non-PE / ELF / Mach-O / Raw Binary Architecture Card */}
            {(!hasDosHeader && !hasFileHeader && !hasOptHeader) && (
              <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 space-y-4">
                <div className="flex items-center gap-2">
                  <FileCheck className="w-5 h-5 text-indigo-600" />
                  <h4 className="font-bold text-xs text-slate-800 uppercase tracking-wider">
                    {binaryInfo.format || 'Binary File Structure & Header Analysis'}
                  </h4>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                  <div className="p-3 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-sans">Binary Format</span>
                    <span className="text-slate-900 font-bold">{binaryInfo.format || 'Unknown'}</span>
                  </div>
                  <div className="p-3 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-sans">Machine Target</span>
                    <span className="text-indigo-600 font-bold">{binaryInfo.architecture || 'Unknown Arch'}</span>
                  </div>
                  <div className="p-3 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-sans">Subsystem / Type</span>
                    <span className="text-slate-800">{binaryInfo.subsystem || 'Standard Executable'}</span>
                  </div>
                  <div className="p-3 bg-white rounded-xl border border-slate-200">
                    <span className="text-slate-400 block text-[10px] uppercase font-sans">Digital Signature</span>
                    <span className={hasAuthenticode ? 'text-emerald-700 font-bold' : 'text-slate-600 font-medium'}>
                      {binaryInfo.digital_signature || 'Unsigned'}
                    </span>
                  </div>
                </div>

                {isELF && (
                  <div className="p-3 bg-white rounded-xl border border-slate-200 text-xs text-slate-600 space-y-1">
                    <p className="font-semibold text-slate-800">Linux ELF Executable Information:</p>
                    <p>• Architecture: <span className="font-mono">{binaryInfo.architecture}</span></p>
                    <p>• Sections count: <span className="font-mono">{sectionsCount} sections parsed</span></p>
                    <p>• Linked shared libraries: <span className="font-mono">{dllNames.length > 0 ? dllNames.join(', ') : 'Statically linked or standalone'}</span></p>
                    <p>• Strip status: <span className="font-mono">{compilersList.join(', ') || 'Standard binary'}</span></p>
                  </div>
                )}

                {isMachO && (
                  <div className="p-3 bg-white rounded-xl border border-slate-200 text-xs text-slate-600 space-y-1">
                    <p className="font-semibold text-slate-800">Apple macOS Mach-O Information:</p>
                    <p>• Slices / Architecture: <span className="font-mono">{binaryInfo.architecture}</span></p>
                    <p>• Code Signature: <span className="font-mono">{binaryInfo.digital_signature}</span></p>
                  </div>
                )}
              </div>
            )}

          {/* Overall File Entropy Gauge */}
          {typeof (binaryInfo as any).overall_entropy === 'number' && (
            <div className="p-4 bg-white rounded-2xl border border-slate-200">
              <h4 className="font-bold text-xs text-slate-800 uppercase tracking-wider flex items-center gap-1.5 mb-3">
                <span>📊</span> Overall File Entropy
              </h4>
              <div className="flex items-center gap-4">
                <span className={`text-sm font-bold px-3 py-1.5 rounded-xl border ${
                  (binaryInfo as any).overall_entropy >= 7.2 ? 'bg-red-50 text-red-700 border-red-200' :
                  (binaryInfo as any).overall_entropy >= 6.5 ? 'bg-orange-50 text-orange-700 border-orange-200' :
                  (binaryInfo as any).overall_entropy >= 5.0 ? 'bg-amber-50 text-amber-700 border-amber-200' :
                  'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}>
                  {((binaryInfo as any).overall_entropy as number).toFixed(3)} / 8.0
                </span>
                <span className="text-xs text-slate-500">
                  {(binaryInfo as any).overall_entropy >= 7.2 ? '⚠ High entropy — possibly packed or encrypted' :
                   (binaryInfo as any).overall_entropy >= 6.5 ? 'High entropy — compressed or encoded content' :
                   (binaryInfo as any).overall_entropy >= 5.0 ? 'Moderate entropy — mixed content' :
                   'Low entropy — normal binary content'}
                </span>
              </div>
            </div>
          )}
        </div>
        )}

        {/* Tab 2: Sections & Dumps */}
        {activeTab === 'sections' && (
          <div className="pt-4 space-y-4">
            {/* Entropy Chart */}
            {Array.isArray(binaryInfo.sections) && binaryInfo.sections.length > 0 && (
              <div className="p-4 bg-white rounded-2xl border border-slate-200">
                <EntropyChart
                  sections={binaryInfo.sections}
                  overallEntropy={typeof (binaryInfo as any).overall_entropy === 'number' ? (binaryInfo as any).overall_entropy : undefined}
                />
              </div>
            )}

            {/* Size Anomalies Alert */}
            {binaryInfo.size_analysis && Object.keys(binaryInfo.size_analysis).length > 0 && (
              <div className="p-3.5 bg-slate-50 rounded-2xl border border-slate-200 text-xs font-mono flex flex-wrap items-center justify-between gap-3">
                <div className="space-x-3 text-slate-600">
                  <span>Physical File: <b>{formatBytes(binaryInfo.size_analysis.physical_size || 0)}</b></span>
                  <span>•</span>
                  <span>Sections Raw Sum: <b>{formatBytes(binaryInfo.size_analysis.sections_raw_total || 0)}</b></span>
                  <span>•</span>
                  <span>Virtual Memory: <b>{formatBytes(binaryInfo.size_analysis.declared_virtual_size || 0)}</b></span>
                </div>

                {binaryInfo.size_analysis.has_overlay && (
                  <span className="px-2.5 py-1 bg-amber-100 text-amber-900 border border-amber-300 rounded-lg text-xs font-bold font-sans">
                    ⚠️ Overlay / Slack Space Detected: {formatBytes(binaryInfo.size_analysis.overlay_size || 0)} at {binaryInfo.size_analysis.overlay_offset || '0x0'}
                  </span>
                )}
              </div>
            )}

            {/* Sections Table with Dump Section Button */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600">
                    <th className="py-2.5 px-3">Name</th>
                    <th className="py-2.5 px-3">Virtual Addr</th>
                    <th className="py-2.5 px-3">Virtual Size</th>
                    <th className="py-2.5 px-3">Raw Offset</th>
                    <th className="py-2.5 px-3">Raw Size</th>
                    <th className="py-2.5 px-3">Entropy</th>
                    <th className="py-2.5 px-3">Characteristics / Flags</th>
                    <th className="py-2.5 px-3 text-right">Dump Section</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {Array.isArray(binaryInfo.sections) && binaryInfo.sections.map((sec, idx) => {
                    const ent = typeof sec.entropy === 'number' ? sec.entropy : 0;
                    const flagsStr = Array.isArray(sec.flags) ? sec.flags.join(', ') : '';
                    return (
                      <tr
                        key={idx}
                        className={`hover:bg-slate-50/60 ${sec.is_wx ? 'bg-rose-50/40' : ''}`}
                      >
                        <td className="py-2.5 px-3 font-bold text-slate-900 flex items-center gap-1.5">
                          <span>{sec.name || `Section_${idx}`}</span>
                          {sec.is_entry_point && (
                            <span className="px-1.5 py-0.2 bg-indigo-100 text-indigo-800 rounded text-[9px] font-sans font-bold">
                              EP
                            </span>
                          )}
                          {sec.is_wx && (
                            <span className="px-1.5 py-0.2 bg-rose-100 text-rose-800 rounded text-[9px] font-sans font-bold" title="Write+Execute permission violation">
                              W^X
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-700">{sec.virtual_address || '0x0'}</td>
                        <td className="py-2.5 px-3 text-slate-700">{formatBytes(sec.virtual_size || 0)}</td>
                        <td className="py-2.5 px-3 text-slate-600">{sec.raw_offset || '0x0'}</td>
                        <td className="py-2.5 px-3 text-slate-600">{formatBytes(sec.raw_size || 0)}</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded font-bold ${
                              ent >= 7.2
                                ? 'bg-rose-100 text-rose-900 border border-rose-200'
                                : ent >= 6.5
                                ? 'bg-amber-100 text-amber-900'
                                : 'bg-slate-100 text-slate-700'
                            }`}
                          >
                            {ent.toFixed(2)}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-[11px] text-slate-500 max-w-xs truncate" title={flagsStr}>
                          {flagsStr || '—'}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <a
                            href={apiClient.getBinaryDumpSectionUrl(jobId, sec.name)}
                            download
                            className="px-2.5 py-1 bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 rounded-lg text-[11px] font-semibold inline-flex items-center gap-1 transition-colors shadow-sm cursor-pointer"
                            title={`Dump raw bytes of section ${sec.name}`}
                          >
                            <Download className="w-3 h-3 text-slate-500" />
                            <span>Dump</span>
                          </a>
                        </td>
                      </tr>
                    );
                  })}
                  {(!Array.isArray(binaryInfo.sections) || binaryInfo.sections.length === 0) && (
                    <tr>
                      <td colSpan={8} className="py-6 text-center text-slate-400 italic">
                        No section headers found in this binary.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 3: Imports & Dangerous APIs */}
        {activeTab === 'imports' && (
          <div className="pt-4 space-y-4">
            {/* Suspicious Win32 / Linux API Callouts */}
            {Array.isArray(binaryInfo.suspicious_apis) && binaryInfo.suspicious_apis.length > 0 && (
              <div className="p-4 bg-rose-50/70 border border-rose-200 rounded-2xl">
                <h4 className="font-bold text-xs text-rose-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-600" />
                  <span>Suspicious High-Risk APIs Imported ({binaryInfo.suspicious_apis.length})</span>
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {binaryInfo.suspicious_apis.map((s: any, idx) => (
                    <div key={idx} className="p-2 bg-white rounded-xl border border-rose-200 text-xs">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="font-mono font-bold text-rose-900">{s.api || s.syscall || 'Unknown API'}</span>
                        <span className="px-1.5 py-0.2 bg-rose-100 text-rose-800 rounded text-[9px] font-bold">
                          {s.severity || 'HIGH'}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono mb-1">{s.dll || 'System Call / Shared Library'}</div>
                      <p className="text-[11px] text-slate-600 leading-snug">{s.description || 'Monitored security API'}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Filter Controls */}
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={importSearch}
                  onChange={(e) => setImportSearch(e.target.value)}
                  placeholder="Filter functions by name..."
                  className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <select
                value={selectedDll}
                onChange={(e) => setSelectedDll(e.target.value)}
                className="px-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl font-mono focus:outline-none"
              >
                <option value="all">All Libraries ({dllNames.length})</option>
                {dllNames.map((dll) => (
                  <option key={dll} value={dll}>
                    {dll} ({Array.isArray(binaryInfo.imports?.[dll]) ? binaryInfo.imports[dll].length : 0})
                  </option>
                ))}
              </select>
            </div>

            {/* Functions Table */}
            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600 sticky top-0">
                    <th className="py-2 px-3">Function Name</th>
                    <th className="py-2 px-3">Library (DLL / Shared Object)</th>
                    <th className="py-2 px-3">Ordinal</th>
                    <th className="py-2 px-3">Address</th>
                    <th className="py-2 px-3">Security Note</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredImports.map((fn, idx) => (
                    <tr
                      key={idx}
                      className={`hover:bg-slate-50/60 ${fn.is_suspicious ? 'bg-amber-50/40' : ''}`}
                    >
                      <td className="py-2 px-3 font-semibold text-slate-900">
                        {fn.name}
                        {fn.is_suspicious && (
                          <span className="ml-1.5 px-1.5 py-0.2 bg-amber-100 text-amber-800 rounded text-[9px] font-sans font-bold">
                            Suspicious
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-indigo-600">{fn.dll}</td>
                      <td className="py-2 px-3 text-slate-500">{fn.ordinal ?? '—'}</td>
                      <td className="py-2 px-3 text-slate-500">{fn.address || '0x0'}</td>
                      <td className="py-2 px-3 text-slate-600 max-w-sm truncate" title={fn.description}>
                        {fn.description || 'Standard API'}
                      </td>
                    </tr>
                  ))}
                  {filteredImports.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-slate-400 italic">
                        No imported functions match your filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 4: Exports */}
        {activeTab === 'exports' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Exported Symbols Table</span>
              <span className="font-mono">{exportsCount} exported functions</span>
            </div>

            {(!Array.isArray(binaryInfo.exports) || binaryInfo.exports.length === 0) ? (
              <p className="text-slate-400 text-xs italic p-4 text-center">
                This executable does not export any public functions or symbols (typical for standard applications).
              </p>
            ) : (
              <div className="overflow-x-auto max-h-[500px]">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600">
                      <th className="py-2 px-3">Symbol / Function Name</th>
                      <th className="py-2 px-3">Ordinal</th>
                      <th className="py-2 px-3">Virtual Address / RVA</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {binaryInfo.exports.map((exp, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/60">
                        <td className="py-2 px-3 font-semibold text-slate-900">{exp.name}</td>
                        <td className="py-2 px-3 text-slate-600">{exp.ordinal ?? '—'}</td>
                        <td className="py-2 px-3 text-indigo-600 font-mono">{exp.address || '0x0'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Resources & Payloads */}
        {activeTab === 'resources' && (
          <div className="pt-4 space-y-4">
            {/* Abnormal Resources Warning */}
            {Array.isArray(binaryInfo.abnormal_resources) && binaryInfo.abnormal_resources.length > 0 && (
              <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl">
                <h4 className="font-bold text-xs text-amber-900 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-600" />
                  <span>Abnormal Embedded Resources Detected ({binaryInfo.abnormal_resources.length})</span>
                </h4>
                <ul className="list-disc list-inside text-xs text-amber-900 space-y-1">
                  {binaryInfo.abnormal_resources.map((ab, idx) => (
                    <li key={idx} className="font-mono">{ab}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Resources Table with Dump Resource Button */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600">
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Name / ID</th>
                    <th className="py-2.5 px-3">Offset</th>
                    <th className="py-2.5 px-3">Size</th>
                    <th className="py-2.5 px-3">% of File</th>
                    <th className="py-2.5 px-3">Entropy</th>
                    <th className="py-2.5 px-3">Payload Indicators</th>
                    <th className="py-2.5 px-3 text-right">Dump Resource</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {Array.isArray(binaryInfo.resources) && binaryInfo.resources.map((res, idx) => {
                    const rEnt = typeof res.entropy === 'number' ? res.entropy : 0;
                    return (
                      <tr
                        key={idx}
                        className={`hover:bg-slate-50/60 ${
                          res.is_embedded_pe ? 'bg-rose-50/40' : res.is_embedded_archive ? 'bg-amber-50/40' : ''
                        }`}
                      >
                        <td className="py-2.5 px-3 font-semibold text-slate-900">{res.type}</td>
                        <td className="py-2.5 px-3 text-indigo-600">{res.name}</td>
                        <td className="py-2.5 px-3 text-slate-600">{res.offset || '0x0'}</td>
                        <td className="py-2.5 px-3 text-slate-800">{formatBytes(res.size || 0)}</td>
                        <td className="py-2.5 px-3 text-slate-500">{res.size_percent ?? 0}%</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded font-bold ${
                              rEnt >= 7.2 ? 'bg-rose-100 text-rose-800' : 'bg-slate-100 text-slate-700'
                            }`}
                          >
                            {rEnt.toFixed(2)}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          {res.is_embedded_pe && (
                            <span className="px-2 py-0.5 bg-rose-100 text-rose-800 rounded text-[10px] font-bold">
                              ⚠️ Embedded PE (MZ)
                            </span>
                          )}
                          {res.is_embedded_archive && (
                            <span className="px-2 py-0.5 bg-amber-100 text-amber-800 rounded text-[10px] font-bold">
                              Embedded Archive
                            </span>
                          )}
                          {!res.is_embedded_pe && !res.is_embedded_archive && res.is_high_entropy && (
                            <span className="px-2 py-0.5 bg-purple-100 text-purple-800 rounded text-[10px] font-semibold">
                              Encrypted / Compressed
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <a
                            href={apiClient.getBinaryDumpResourceUrl(jobId, res.type, res.name)}
                            download
                            className="px-2.5 py-1 bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 rounded-lg text-[11px] font-semibold inline-flex items-center gap-1 transition-colors shadow-sm cursor-pointer"
                            title={`Dump resource payload (${res.type}/${res.name})`}
                          >
                            <Download className="w-3 h-3 text-slate-500" />
                            <span>Dump</span>
                          </a>
                        </td>
                      </tr>
                    );
                  })}
                  {(!Array.isArray(binaryInfo.resources) || binaryInfo.resources.length === 0) && (
                    <tr>
                      <td colSpan={8} className="py-6 text-center text-slate-400 italic">
                        No resource directory entries found in this binary.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 6: Strings & Search */}
        {activeTab === 'strings' && (
          <div className="pt-4 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={stringSearch}
                  onChange={(e) => setStringSearch(e.target.value)}
                  placeholder="Search ASCII and Unicode strings..."
                  className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {/* Category Pills */}
              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl text-xs font-semibold">
                <button
                  onClick={() => setStringCategory('all')}
                  className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                    stringCategory === 'all' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  All ({binaryInfo.strings?.total_count || 0})
                </button>
                <button
                  onClick={() => setStringCategory('network')}
                  className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                    stringCategory === 'network' ? 'bg-white text-indigo-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Network / IPs ({Array.isArray(binaryInfo.strings?.network) ? binaryInfo.strings.network.length : 0})
                </button>
                <button
                  onClick={() => setStringCategory('commands')}
                  className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                    stringCategory === 'commands' ? 'bg-white text-rose-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Commands / LOLBins ({Array.isArray(binaryInfo.strings?.commands) ? binaryInfo.strings.commands.length : 0})
                </button>
                <button
                  onClick={() => setStringCategory('file_paths')}
                  className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                    stringCategory === 'file_paths' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  File Paths ({Array.isArray(binaryInfo.strings?.file_paths) ? binaryInfo.strings.file_paths.length : 0})
                </button>
                <button
                  onClick={() => setStringCategory('registry')}
                  className={`px-3 py-1 rounded-lg transition-colors cursor-pointer ${
                    stringCategory === 'registry' ? 'bg-white text-purple-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Registry ({Array.isArray(binaryInfo.strings?.registry) ? binaryInfo.strings.registry.length : 0})
                </button>
              </div>
            </div>

            {/* String Length Filter Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-50 border border-slate-200/90 rounded-2xl text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-slate-700 flex items-center gap-1">
                  <span>📏</span>
                  <span>Length Filter:</span>
                </span>
                <div className="flex items-center gap-1.5">
                  <input
                    type="number"
                    min="0"
                    max="10000"
                    placeholder="Min (e.g. 5)"
                    value={minStrLength}
                    onChange={(e) => setMinStrLength(e.target.value)}
                    className="w-20 px-2.5 py-1 text-xs bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                    title="Minimum string length in characters"
                  />
                  <span className="text-slate-400 font-mono">–</span>
                  <input
                    type="number"
                    min="0"
                    max="10000"
                    placeholder="Max (e.g. 64)"
                    value={maxStrLength}
                    onChange={(e) => setMaxStrLength(e.target.value)}
                    className="w-20 px-2.5 py-1 text-xs bg-white border border-slate-300 rounded-lg text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                    title="Maximum string length in characters"
                  />
                </div>

                {/* Quick Presets */}
                <div className="flex items-center gap-1 ml-1 sm:ml-2">
                  <button
                    type="button"
                    onClick={() => { setMinStrLength(''); setMaxStrLength(''); }}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      !minStrLength && !maxStrLength ? 'bg-indigo-600 text-white' : 'bg-slate-200 hover:bg-slate-300 text-slate-700'
                    }`}
                  >
                    Any
                  </button>
                  <button
                    type="button"
                    onClick={() => { setMinStrLength('5'); setMaxStrLength('15'); }}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      minStrLength === '5' && maxStrLength === '15' ? 'bg-blue-600 text-white' : 'bg-slate-200 hover:bg-slate-300 text-slate-700'
                    }`}
                  >
                    Short (5–15)
                  </button>
                  <button
                    type="button"
                    onClick={() => { setMinStrLength('16'); setMaxStrLength('64'); }}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      minStrLength === '16' && maxStrLength === '64' ? 'bg-blue-600 text-white' : 'bg-slate-200 hover:bg-slate-300 text-slate-700'
                    }`}
                  >
                    Medium (16–64)
                  </button>
                  <button
                    type="button"
                    onClick={() => { setMinStrLength('65'); setMaxStrLength(''); }}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      minStrLength === '65' && !maxStrLength ? 'bg-blue-600 text-white' : 'bg-slate-200 hover:bg-slate-300 text-slate-700'
                    }`}
                  >
                    Long (65+)
                  </button>
                  {(minStrLength !== '5' || Boolean(maxStrLength)) && (
                    <button
                      type="button"
                      onClick={() => { setMinStrLength('5'); setMaxStrLength(''); }}
                      className="text-[11px] text-rose-600 hover:text-rose-700 underline font-medium ml-1 cursor-pointer"
                    >
                      Reset (Min 5)
                    </button>
                  )}
                </div>
              </div>

              {/* Counter Indicator */}
              <div className="text-slate-500 font-mono text-[11px] flex items-center gap-1.5">
                <span>Matching:</span>
                <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded-md border border-slate-200">
                  {filteredStrings.length}
                </span>
                <span>strings</span>
              </div>
            </div>

            {/* Strings Terminal Display */}
            <div className="p-4 bg-slate-50 text-slate-800 rounded-2xl border border-slate-200 text-xs font-mono max-h-[500px] overflow-y-auto space-y-1 shadow-inner">
              {filteredStrings.map((s, idx) => {
                const renamedVal = getRenamed(s);
                const hasRename = renamedVal !== s;
                return (
                  <div key={idx} className="hover:bg-slate-100/80 py-1 px-1.5 rounded flex items-center justify-between gap-2 break-all group transition-colors">
                    <div className="flex items-start gap-2 flex-1 min-w-0">
                      <span className="text-slate-400 select-none text-[10px] w-8 shrink-0 text-right pt-0.5">
                        {idx + 1}
                      </span>
                      <span className={hasRename ? 'text-slate-400 line-through opacity-75' : 'text-slate-800'}>
                        <ReferencedText text={s} workspaceJobs={workspaceJobs} onSelectJob={onSelectJob} />
                      </span>
                      {hasRename && (
                        <span className="text-indigo-700 font-bold bg-indigo-50 px-1.5 py-0.2 rounded border border-indigo-200 text-[11px] shrink-0">
                          ➔ {renamedVal}
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleOpenRename(s, 'string')}
                      className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-indigo-600 hover:bg-white p-1 rounded border border-transparent hover:border-slate-200 transition-all cursor-pointer text-[10px] font-sans flex items-center gap-1 shrink-0"
                      title="Rename this string symbol"
                    >
                      <Edit3 className="w-3 h-3 text-indigo-600" />
                      <span>Rename</span>
                    </button>
                  </div>
                );
              })}
              {filteredStrings.length === 0 && (
                <p className="text-slate-400 italic text-center py-4">No strings found matching your search.</p>
              )}
            </div>
          </div>
        )}

        {/* Tab 7: Compilers & Protectors (DIE) */}
        {activeTab === 'compilers' && (
          <div className="pt-4 space-y-4">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
              <h4 className="font-bold text-xs text-slate-800 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-emerald-600" />
                <span>Compiler & Linker Fingerprints (Detect It Easy Engine)</span>
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
                <div className="p-3 bg-white rounded-xl border border-slate-200">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold mb-1">
                    Detected Compilers & Toolchains
                  </span>
                  <div className="space-y-1">
                    {compilersList.length > 0 ? (
                      compilersList.map((comp, idx) => (
                        <div key={idx} className="font-mono text-xs font-bold text-slate-800">
                          • {comp}
                        </div>
                      ))
                    ) : (
                      <span className="text-slate-500 text-xs italic">Unknown / Generic Compiler</span>
                    )}
                  </div>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200">
                  <span className="text-slate-400 block text-[10px] uppercase font-semibold mb-1">
                    Packers & Crypters Detected
                  </span>
                  <div className="space-y-1">
                    {packersList.length > 0 ? (
                      packersList.map((p, idx) => (
                        <div key={idx} className="font-mono text-xs font-bold text-rose-700">
                          ⚠️ {p}
                        </div>
                      ))
                    ) : (
                      <span className="text-emerald-700 font-semibold text-xs">✓ None detected (Standard executable file)</span>
                    )}
                  </div>
                </div>
              </div>

              {/* DIE Detection Details */}
              {Array.isArray(binaryInfo.packers_and_compilers?.detection_details) &&
                binaryInfo.packers_and_compilers.detection_details.length > 0 && (
                  <div className="p-3 bg-white rounded-xl border border-slate-200 mb-3">
                    <span className="text-[10px] text-slate-400 uppercase font-sans font-semibold block mb-1">
                      Static Signature Markers & Detection Details
                    </span>
                    <ul className="list-disc list-inside text-xs text-slate-700 space-y-1">
                      {binaryInfo.packers_and_compilers.detection_details.map((d, idx) => (
                        <li key={idx} className="font-mono">{d}</li>
                      ))}
                    </ul>
                  </div>
                )}

              {/* Rich Header Tools Table */}
              {detectedTools.length > 0 && (
                <div className="mt-3">
                  <span className="text-[10px] text-slate-400 uppercase font-sans font-semibold block mb-1">
                    Microsoft Visual Studio Rich Header Records
                  </span>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs font-mono border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 bg-white text-slate-600">
                          <th className="py-2 px-3 text-left">Tool ID</th>
                          <th className="py-2 px-3 text-left">Identified Build Component</th>
                          <th className="py-2 px-3 text-right">Count</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 bg-white">
                        {detectedTools.map((t, idx) => (
                          <tr key={idx} className="hover:bg-slate-50">
                            <td className="py-1.5 px-3 text-indigo-600">{t.tool_id}</td>
                            <td className="py-1.5 px-3 text-slate-800">{t.name || t.compiler}</td>
                            <td className="py-1.5 px-3 text-right text-slate-500">{t.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 8: Capstone Entry Point Disassembly */}
        {activeTab === 'disassembly' && (binaryInfo as any).disassembly && (
          <div className="pt-4 space-y-4">
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">
                  Address of Entry Point (RVA)
                </span>
                <span className="text-base font-mono font-bold text-indigo-700">
                  {getRenamed((binaryInfo as any).disassembly.entry_point || '0x0')}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-slate-500 font-medium hidden sm:inline">
                  Capstone Multi-Architecture Disassembly
                </span>
                <button
                  type="button"
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
              </div>
            </div>

            {Array.isArray((binaryInfo as any).disassembly.suspicious_patterns) &&
              (binaryInfo as any).disassembly.suspicious_patterns.length > 0 && (
                <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl">
                  <span className="text-xs font-bold text-rose-900 block mb-2 flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-rose-600" />
                    Suspicious Entry Point Instruction Patterns Detected:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {(binaryInfo as any).disassembly.suspicious_patterns.map((pat: string, idx: number) => (
                      <span
                        key={idx}
                        className="text-xs px-2.5 py-1 rounded-lg bg-rose-100 text-rose-800 border border-rose-300 font-mono font-semibold"
                      >
                        ⚠️ {pat}
                      </span>
                    ))}
                  </div>
                </div>
              )}

            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white font-mono text-xs">
              <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-left text-slate-800">
                  <thead className="bg-slate-100 text-slate-500 text-[11px] uppercase sticky top-0 border-b border-slate-200">
                    <tr>
                      <th className="py-2.5 px-4 w-28">Address</th>
                      <th className="py-2.5 px-4 w-24">Mnemonic</th>
                      <th className="py-2.5 px-4">Operands</th>
                      <th className="py-2.5 px-4 w-40 text-right">Machine Hex</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {Array.isArray((binaryInfo as any).disassembly.instructions) &&
                      (binaryInfo as any).disassembly.instructions.map((rawInst: any, idx: number) => {
                        const inst = applyToInstruction(rawInst);
                        return (
                          <tr key={idx} className="hover:bg-slate-50 font-mono">
                            <td className="py-1.5 px-4 text-indigo-600 font-bold">{inst.address}</td>
                            <td className="py-1.5 px-4 text-amber-700 font-bold">{inst.mnemonic}</td>
                            <td className="py-1.5 px-4 text-slate-700">{inst.op_str}</td>
                            <td className="py-1.5 px-4 text-right text-slate-400 text-[10px] tracking-widest">{inst.bytes}</td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Tab 8b: C/C++ High-Level Decompiler */}
        {activeTab === 'decompiler' && (
          <div className="pt-4">
            <BinaryDecompilerCard binaryInfo={binaryInfo} filename={_filename} />
          </div>
        )}

        {/* Tab 9: Anti-Analysis & Evasion */}
        {activeTab === 'anti_analysis' && (
          <div className="pt-4 space-y-4">
            {antiAnalysis ? (
              <AntiAnalysisInspectorCard
                antiAnalysis={antiAnalysis}
                filename={_filename}
                category="binary"
              />
            ) : (binaryInfo as any).anti_analysis ? (
              <>
                <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl">
                  <h4 className="text-sm font-bold text-amber-900 mb-1 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-amber-700" />
                    Anti-Analysis, Debugger Detection & Timing Evasion Heuristics
                  </h4>
                  <p className="text-xs text-amber-800 leading-relaxed">
                    Malware samples query system debug status or sleep for extended durations to evade sandbox automated analysis.
                  </p>
                </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <span className="text-xs font-bold text-slate-800 block mb-2 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-slate-500" />
                  Anti-Debugging APIs
                </span>
                {Array.isArray((binaryInfo as any).anti_analysis.anti_debugging) &&
                (binaryInfo as any).anti_analysis.anti_debugging.length > 0 ? (
                  <div className="space-y-1.5">
                    {(binaryInfo as any).anti_analysis.anti_debugging.map((api: string, idx: number) => (
                      <div key={idx} className="p-2 bg-white rounded-lg border border-slate-200 font-mono text-xs text-rose-700 font-bold">
                        ⚠️ {api}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No standard Win32 anti-debugging APIs found in import table.</p>
                )}
              </div>

              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <span className="text-xs font-bold text-slate-800 block mb-2 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-slate-500" />
                  Timing Evasion & Delay Execution
                </span>
                {Array.isArray((binaryInfo as any).anti_analysis.timing_evasion) &&
                (binaryInfo as any).anti_analysis.timing_evasion.length > 0 ? (
                  <div className="space-y-1.5">
                    {(binaryInfo as any).anti_analysis.timing_evasion.map((api: string, idx: number) => (
                      <div key={idx} className="p-2 bg-white rounded-lg border border-slate-200 font-mono text-xs text-amber-800 font-bold">
                        ⏱️ {api}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No suspicious delay execution APIs observed.</p>
                )}
              </div>
            </div>
          </>
        ) : null}
      </div>
    )}

        {/* Tab 10: Authenticode Signatures & Trust Chain */}
        {activeTab === 'authenticode' && (binaryInfo as any).authenticode && (() => {
          const auth = (binaryInfo as any).authenticode;
          const certs = Array.isArray(auth.certificates) ? auth.certificates : [];
          const isSigned = auth.is_signed;
          const trustStatus = auth.trust_status || (isSigned ? 'SIGNED' : 'UNSIGNED');
          const isSelfSigned = trustStatus === 'SELF_SIGNED_UNTRUSTED';
          const isExpired = trustStatus === 'EXPIRED';

          return (
            <div className="pt-4 space-y-4">
              {/* Trust Overview Card */}
              <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200">
                <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-200 mb-4 gap-3">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-0.5">
                      Authenticode Digital Signature & Certificate Trust Chain
                    </span>
                    <div className="flex flex-wrap items-center gap-2 mt-1">
                      <span
                        className={`text-xs px-3 py-1 rounded-full font-bold uppercase ${
                          !isSigned
                            ? 'bg-slate-200 text-slate-700'
                            : isSelfSigned
                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                            : isExpired
                            ? 'bg-amber-100 text-amber-800 border border-amber-300'
                            : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                        }`}
                      >
                        {trustStatus.replace(/_/g, ' ')}
                      </span>

                      {auth.signer_name && auth.signer_name !== 'Unknown' && (
                        <span className="text-xs font-semibold text-slate-800 bg-white px-2.5 py-1 rounded-lg border border-slate-200">
                          Signer: {auth.signer_name}
                        </span>
                      )}

                      {auth.has_timestamp && (
                        <span className="text-xs font-medium text-blue-700 bg-blue-50 border border-blue-200 px-2.5 py-1 rounded-lg flex items-center gap-1.5">
                          <span>✓ Counter-Signed</span>
                          <span className="text-[10px] text-blue-500 font-mono">({auth.timestamp_type || 'Timestamped'})</span>
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="text-right text-[11px] font-mono text-slate-400">
                    <div>Offset: {auth.table_offset || 'N/A'}</div>
                    <div>Size: {auth.table_size ? `${auth.table_size} bytes` : 'N/A'}</div>
                  </div>
                </div>

                {/* Anomaly Callouts */}
                {Array.isArray(auth.anomalies) && auth.anomalies.length > 0 && (
                  <div className="mb-4 p-3 bg-amber-50/80 border border-amber-200 rounded-xl text-xs text-amber-900 space-y-1">
                    <span className="font-bold flex items-center gap-1.5 text-amber-800">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                      Authenticode Chain Anomalies Detected:
                    </span>
                    {auth.anomalies.map((anom: string, aIdx: number) => (
                      <p key={aIdx} className="text-amber-800/90 pl-5">• {anom}</p>
                    ))}
                  </div>
                )}

                {/* Certificate Chain Visual Hierarchy */}
                {certs.length > 0 ? (
                  <div className="space-y-3">
                    <span className="text-xs font-bold text-slate-800 block">
                      Evaluated Certificate Chain ({certs.length} Certificate{certs.length > 1 ? 's' : ''}):
                    </span>

                    <div className="space-y-3">
                      {certs.map((cert: any, idx: number) => {
                        const isCertExpired = cert.is_expired;
                        const isCertSelfSigned = cert.is_self_signed;

                        return (
                          <div
                            key={idx}
                            className={`p-4 bg-white rounded-xl border transition-all ${
                              isCertSelfSigned
                                ? 'border-amber-300 shadow-2xs'
                                : isCertExpired
                                ? 'border-amber-200'
                                : 'border-slate-200'
                            }`}
                          >
                            <div className="flex flex-wrap items-start justify-between gap-2 pb-2.5 border-b border-slate-100">
                              <div className="flex items-center gap-2">
                                <span className="w-5 h-5 rounded-full bg-slate-100 text-slate-700 text-[10px] font-bold flex items-center justify-center font-mono">
                                  #{idx + 1}
                                </span>
                                <div>
                                  <h5 className="font-bold text-xs text-slate-900">
                                    {cert.display_name || cert.subject?.common_name || cert.subject?.organization || `Certificate #${idx + 1}`}
                                  </h5>
                                  <span className="text-[10px] text-slate-400 font-mono">
                                    Role: <span className="font-semibold text-slate-600">{cert.role || 'X.509 Certificate'}</span>
                                  </span>
                                </div>
                              </div>

                              <div className="flex items-center gap-1.5">
                                {isCertSelfSigned && (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800">
                                    Self-Signed
                                  </span>
                                )}
                                {isCertExpired ? (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800">
                                    Expired
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800">
                                    Valid
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="mt-2.5 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                              <div>
                                <span className="text-slate-400 text-[10px] uppercase block font-semibold">Issuer</span>
                                <span className="text-slate-700 font-medium">
                                  {cert.issuer?.display || cert.issuer?.common_name || cert.issuer?.organization || cert.issuer || 'Self-Issued'}
                                </span>
                              </div>
                              <div>
                                <span className="text-slate-400 text-[10px] uppercase block font-semibold">Validity Period</span>
                                <span className="text-slate-700 font-mono text-[11px]">
                                  {cert.valid_from ? new Date(cert.valid_from).toLocaleDateString() : 'N/A'} —{' '}
                                  {cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : 'N/A'}
                                </span>
                              </div>
                              {cert.serial_number && (
                                <div>
                                  <span className="text-slate-400 text-[10px] uppercase block font-semibold">Serial Number</span>
                                  <span className="text-slate-700 font-mono text-[10px] break-all">
                                    {cert.serial_number}
                                  </span>
                                </div>
                              )}
                              {cert.signature_algorithm && (
                                <div>
                                  <span className="text-slate-400 text-[10px] uppercase block font-semibold">Signature Algorithm</span>
                                  <span className="text-slate-700 font-mono text-[11px]">
                                    {cert.signature_algorithm}
                                  </span>
                                </div>
                              )}
                            </div>

                            {cert.sha256_fingerprint && (
                              <div className="mt-2.5 pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] font-mono">
                                <span className="text-slate-400 text-[10px] uppercase">SHA-256 Fingerprint:</span>
                                <span className="text-slate-600 text-[10px] break-all select-all">
                                  {cert.sha256_fingerprint}
                                </span>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">
                    No embedded X.509 digital certificates discovered in the Windows Security Directory table.
                  </p>
                )}
              </div>
            </div>
          );
        })()}

        {/* Tab 11: Exploit Mitigations & Hardening (PE + ELF) */}
        {activeTab === 'mitigations' && (() => {
          const pe = (binaryInfo as any).pe_mitigations;
          const elf = (binaryInfo as any).elf_mitigations;
          const cs = elf?.checksec?.checks || {};
          const hasChecksec = Object.keys(cs).length > 0;

          const MitigCell = ({ label, ok, val, tooltip }: { label: string; ok: boolean | null; val?: string; tooltip?: string }) => (
            <div className="p-3 bg-white rounded-xl border border-slate-200" title={tooltip}>
              <span className="text-[10px] text-slate-400 uppercase font-semibold tracking-wide block mb-1">{label}</span>
              {val ? (
                <span className={`text-xs font-bold ${ok === true ? 'text-emerald-700' : ok === false ? 'text-rose-700' : 'text-slate-700'}`}>{val}</span>
              ) : (
                <span className={`text-xs font-bold ${ok === true ? 'text-emerald-700' : ok === false ? 'text-rose-700' : 'text-slate-500'}`}>
                  {ok === true ? '✓ Enabled' : ok === false ? '✗ Disabled' : '? Unknown'}
                </span>
              )}
            </div>
          );

          return (
            <div className="pt-4 space-y-4">
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-indigo-600" />
                    Binary Exploit Mitigations &amp; Hardening
                  </h4>
                  {hasChecksec && (
                    <span className="text-[10px] font-semibold px-2 py-1 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded-lg">
                      ⚡ checksec v3.2
                    </span>
                  )}
                  {pe && (
                    <span className="text-[10px] font-semibold px-2 py-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-lg">
                      Windows PE checksec
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 mb-4">
                  {pe
                    ? 'Security mitigations verified across Windows PE Optional Header and DllCharacteristics flags.'
                    : 'Compiler and linker security flags verified across ELF program headers' + (hasChecksec ? ' and augmented by checksec (slimm609/checksec).' : '.')}
                </p>

                {pe && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      <MitigCell label="DEP / NX (NX_COMPAT)" ok={pe.has_dep} tooltip="Data Execution Prevention — blocks shellcode execution in heap and stack memory." />
                      <MitigCell label="ASLR (DYNAMIC_BASE)" ok={pe.has_aslr} tooltip="Address Space Layout Randomization — randomizes base image memory address." />
                      <MitigCell label="High Entropy VA (64-bit)" ok={pe.has_high_entropy} tooltip="64-bit Address Space Layout Randomization with 1TB+ virtual entropy." />
                      <MitigCell label="Control Flow Guard (CFG)" ok={pe.has_cfg} tooltip="Control Flow Guard — compiler-based protection against indirect call hijacking." />
                      <MitigCell label="SafeSEH / Structured Exception" ok={pe.has_safeseh} tooltip="Structured Exception Handling protection — blocks SEH overwrite exploits." />
                      <MitigCell label="Force Integrity" ok={pe.has_force_integrity} tooltip="Kernel-enforced signature verification check at load time." />
                      <MitigCell label="Authenticode Signature" ok={pe.has_authenticode} tooltip="Signed with valid or embedded Authenticode digital certificate." />
                    </div>

                    {pe.missing_mitigations && pe.missing_mitigations.length > 0 && (
                      <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl">
                        <span className="text-xs font-bold text-amber-800 block mb-2">Missing Exploit Defenses ({pe.missing_mitigations.length}):</span>
                        <div className="space-y-1">
                          {pe.missing_mitigations.map((mit: string, i: number) => (
                            <div key={i} className="flex items-start gap-1.5 text-xs text-amber-700">
                              <span className="shrink-0 mt-0.5">✗</span>
                              <span>{mit}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {elf && (
                  <div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      <MitigCell label="NX / DEP (Stack)" ok={elf.has_nx} tooltip="No-eXecute bit on stack (PT_GNU_STACK). Prevents shellcode execution on the stack." />
                      <MitigCell label="PIE / ASLR" ok={elf.has_pie} tooltip="Position-Independent Executable — enables ASLR." />
                      <MitigCell
                        label="RELRO"
                        ok={elf.relro_type ? elf.relro_type.toLowerCase().includes('full') : elf.has_relro}
                        val={elf.relro_type || (elf.has_relro ? 'Partial' : 'None')}
                        tooltip="Relocation Read-Only — makes GOT/PLT segments read-only after startup."
                      />
                      <MitigCell label="Stack Canary" ok={elf.has_canary} tooltip="Stack canary (__stack_chk_fail) detects buffer overflows." />
                      <MitigCell
                        label="Symbols"
                        ok={!elf.is_stripped}
                        val={elf.is_stripped ? 'Stripped' : 'Present'}
                        tooltip="Symbol table. Stripped = anti-forensics technique."
                      />
                      {hasChecksec && (
                        <>
                          <MitigCell label="CFI" ok={elf.has_cfi ?? null} val={cs.cfi?.value || (elf.has_cfi ? 'Enabled' : 'Disabled')} tooltip="Control Flow Integrity — restricts valid jump targets." />
                          <MitigCell label="SafeStack" ok={elf.has_safestack ?? null} val={cs.safestack?.value || (elf.has_safestack ? 'Found' : 'Not found')} tooltip="SafeStack separates safe/unsafe stack frames." />
                          <MitigCell label="Stack Clash" ok={elf.has_stack_clash_protection ?? null} val={cs.stack_clash?.value || '?'} tooltip="Stack Clash Protection prevents stack/heap collision." />
                          <MitigCell label="Fortify Source" ok={cs.fortify_source?.status === 'green' ? true : null} val={elf.fortify_source || cs.fortify_source?.value || 'Unknown'} tooltip="_FORTIFY_SOURCE — bounds checking on stdlib functions." />
                          <MitigCell label="Sanitizers" ok={elf.sanitizers && elf.sanitizers !== 'None' ? true : null} val={elf.sanitizers || 'None'} tooltip="Compiler sanitizers (ASan, UBSan, etc.)." />
                        </>
                      )}
                    </div>

                    {(elf.rpath || elf.runpath) && (
                      <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded-xl">
                        <span className="text-[10px] text-amber-600 uppercase font-semibold block mb-1">⚠ Insecure Library Paths</span>
                        {elf.rpath && <p className="text-xs text-amber-800 font-mono">RPATH: {elf.rpath}</p>}
                        {elf.runpath && <p className="text-xs text-amber-800 font-mono">RUNPATH: {elf.runpath}</p>}
                      </div>
                    )}

                    {elf.missing_mitigations && elf.missing_mitigations.length > 0 && (
                      <div className="mt-3 p-3 bg-rose-50 border border-rose-200 rounded-xl">
                        <span className="text-xs font-bold text-rose-800 block mb-2">Missing Security Mitigations:</span>
                        <div className="space-y-1">
                          {elf.missing_mitigations.map((mit: string, i: number) => (
                            <div key={i} className="flex items-start gap-1.5 text-xs text-rose-700">
                              <span className="shrink-0 mt-0.5">✗</span>
                              <span>{mit}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })()}

        {/* Tab 11: Shellcode Forensics & PIC Disassembly */}
        {activeTab === 'shellcode' && (() => {
          const sc = (binaryInfo as any).shellcode;
          if (!sc) {
            return (
              <div className="p-8 text-center text-slate-400">
                <Cpu className="w-10 h-10 mx-auto mb-2 opacity-50" />
                <p className="text-sm font-semibold">No raw shellcode structures detected in this file.</p>
              </div>
            );
          }

          return (
            <div className="pt-4 space-y-5">
              {/* Architecture & Sled Banner */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-rose-100 text-rose-700 rounded-xl">
                    <Cpu className="w-6 h-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="font-bold text-sm text-slate-900">
                        Position-Independent Shellcode Payload
                      </h4>
                      <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                        {sc.architecture || 'x86'}
                      </span>
                      {sc.confidence && (
                        <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          {Math.round(sc.confidence * 100)}% Confidence
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Analyzed via Capstone Multi-Architecture Disassembly & Heuristic Signature Engine
                    </p>
                  </div>
                </div>

                {sc.nop_sled?.detected && (
                  <div className="px-3 py-1.5 bg-rose-50 border border-rose-300 rounded-xl text-rose-800 text-xs font-bold flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>NOP Sled Detected: {sc.nop_sled.length} bytes (Offset 0x{(sc.nop_sled.offset ?? 0).toString(16)})</span>
                  </div>
                )}
              </div>

              {/* Heuristics Cards Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className={`p-3 rounded-2xl border ${sc.heuristics?.has_peb_traversal ? 'bg-rose-50 border-rose-200 text-rose-900' : 'bg-slate-50 border-slate-200 text-slate-500'}`}>
                  <span className="text-[10px] uppercase font-bold tracking-wider block mb-1">
                    PEB / TEB Traversal
                  </span>
                  <span className="font-bold text-sm flex items-center gap-1.5">
                    {sc.heuristics?.has_peb_traversal ? '⚠️ fs:[30h] / gs:[60h]' : '✓ None'}
                  </span>
                </div>

                <div className={`p-3 rounded-2xl border ${sc.heuristics?.has_direct_syscalls ? 'bg-rose-50 border-rose-200 text-rose-900' : 'bg-slate-50 border-slate-200 text-slate-500'}`}>
                  <span className="text-[10px] uppercase font-bold tracking-wider block mb-1">
                    Direct Syscalls
                  </span>
                  <span className="font-bold text-sm flex items-center gap-1.5">
                    {sc.heuristics?.has_direct_syscalls ? '⚠️ Native Syscalls' : '✓ Standard API'}
                  </span>
                </div>

                <div className={`p-3 rounded-2xl border ${sc.heuristics?.has_api_hashing ? 'bg-rose-50 border-rose-200 text-rose-900' : 'bg-slate-50 border-slate-200 text-slate-500'}`}>
                  <span className="text-[10px] uppercase font-bold tracking-wider block mb-1">
                    API Hashing Loops
                  </span>
                  <span className="font-bold text-sm flex items-center gap-1.5">
                    {sc.heuristics?.has_api_hashing ? '⚠️ ROR-13 / Cobalt Strike' : '✓ Unhashed'}
                  </span>
                </div>

                <div className={`p-3 rounded-2xl border ${sc.heuristics?.has_get_eip ? 'bg-amber-50 border-amber-200 text-amber-900' : 'bg-slate-50 border-slate-200 text-slate-500'}`}>
                  <span className="text-[10px] uppercase font-bold tracking-wider block mb-1">
                    Get-EIP / Delta
                  </span>
                  <span className="font-bold text-sm flex items-center gap-1.5">
                    {sc.heuristics?.has_get_eip ? '⚠️ Call/Pop / FPU' : '✓ Absolute'}
                  </span>
                </div>
              </div>

              {/* Resolved API Hashes Table */}
              {Array.isArray(sc.resolved_api_hashes) && sc.resolved_api_hashes.length > 0 && (
                <div className="p-4 bg-white rounded-2xl border border-slate-200 shadow-2xs">
                  <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-600" />
                    <span>Pre-Calculated API Hashes Resolved ({sc.resolved_api_hashes.length} Win32 Functions)</span>
                  </h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-slate-50 text-slate-500 text-[10px] uppercase border-b border-slate-200">
                        <tr>
                          <th className="py-2 px-3">Hash</th>
                          <th className="py-2 px-3">Resolved Function</th>
                          <th className="py-2 px-3">Target Library</th>
                          <th className="py-2 px-3">Offset</th>
                          <th className="py-2 px-3">Capability Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {sc.resolved_api_hashes.map((h: any, i: number) => (
                          <tr key={i} className="hover:bg-slate-50">
                            <td className="py-1.5 px-3 text-rose-700 font-bold">{h.hash}</td>
                            <td className="py-1.5 px-3 text-indigo-700 font-bold">{h.function}</td>
                            <td className="py-1.5 px-3 text-slate-600">{h.library}</td>
                            <td className="py-1.5 px-3 text-slate-400">{h.offset}</td>
                            <td className="py-1.5 px-3 text-slate-700 font-sans">{h.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Network / C2 Socket Configuration */}
              {Array.isArray(sc.network_indicators) && sc.network_indicators.length > 0 && (
                <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl">
                  <h4 className="text-xs font-bold text-rose-900 uppercase tracking-wider mb-2 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-600" />
                    <span>Hardcoded C2 Command & Control Sockets ({sc.network_indicators.length} endpoints)</span>
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {sc.network_indicators.map((net: any, i: number) => (
                      <span key={i} className="px-3 py-1 bg-white border border-rose-300 rounded-xl font-mono text-xs font-bold text-rose-800 shadow-2xs">
                        {net.ip}:{net.port} <span className="text-[10px] text-slate-400 font-normal">({net.offset})</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Dynamic Stack Strings */}
              {Array.isArray(sc.stack_strings) && sc.stack_strings.length > 0 && (
                <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                  <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-slate-600" />
                    <span>Dynamic Stack Strings Reconstructed ({sc.stack_strings.length})</span>
                  </h4>
                  <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto p-2 bg-white rounded-xl border border-slate-200 font-mono text-xs">
                    {sc.stack_strings.map((str: string, i: number) => (
                      <span key={i} className="px-2 py-0.5 bg-slate-100 rounded text-slate-800 border border-slate-200">
                        {str}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Shellcode Disassembly Listing */}
              {Array.isArray(sc.disassembly) && sc.disassembly.length > 0 && (
                <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white font-mono text-xs">
                  <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                      Full Instruction Disassembly Listing ({sc.disassembly.length} instructions)
                    </span>
                    <span className="text-[11px] text-slate-500 font-sans">
                      Capstone {sc.architecture}
                    </span>
                  </div>
                  <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                    <table className="w-full text-left text-slate-800">
                      <thead className="bg-slate-100 text-slate-500 text-[10px] uppercase sticky top-0 border-b border-slate-200">
                        <tr>
                          <th className="py-2 px-4 w-28">Address</th>
                          <th className="py-2 px-4 w-24">Mnemonic</th>
                          <th className="py-2 px-4">Operands</th>
                          <th className="py-2 px-4 w-40 text-right">Machine Hex</th>
                          <th className="py-2 px-4">Forensic Note</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-mono">
                        {sc.disassembly.map((rawInst: any, idx: number) => {
                          const inst = applyToInstruction(rawInst);
                          return (
                            <tr key={idx} className={inst.is_suspicious ? 'bg-rose-50/70 hover:bg-rose-100/70' : 'hover:bg-slate-50'}>
                              <td className="py-1.5 px-4 text-indigo-600 font-bold">{inst.address}</td>
                              <td className={`py-1.5 px-4 font-bold ${inst.is_suspicious ? 'text-rose-700' : 'text-amber-700'}`}>{inst.mnemonic}</td>
                              <td className="py-1.5 px-4 text-slate-700">{inst.op_str}</td>
                              <td className="py-1.5 px-4 text-right text-slate-400 text-[10px] tracking-widest">{inst.bytes}</td>
                              <td className="py-1.5 px-4">
                                {inst.note && (
                                  <span className="text-[11px] font-sans font-semibold text-rose-800 px-2 py-0.5 rounded-full bg-rose-100 border border-rose-300">
                                    {inst.note}
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
              )}
            </div>
          );
        })()}
      </div>

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
