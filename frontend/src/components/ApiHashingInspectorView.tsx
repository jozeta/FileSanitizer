import React, { useState, useMemo } from 'react';
import {
  Hash,
  Copy,
  Check,
  Search,
  ExternalLink,
  Layers,
  Sparkles
} from 'lucide-react';
import { ApiHashMatch } from '../types';

interface ApiHashingInspectorViewProps {
  matches: ApiHashMatch[];
  filename?: string;
  onOpenXrefs?: (symbol: string) => void;
  onJumpToAddress?: (address: string) => void;
}

export const ApiHashingInspectorView: React.FC<ApiHashingInspectorViewProps> = ({
  matches,
  filename = 'sample.bin',
  onOpenXrefs,
  onJumpToAddress
}) => {
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [copiedYara, setCopiedYara] = useState<boolean>(false);
  const [showYaraModal, setShowYaraModal] = useState<boolean>(false);

  const filteredMatches = useMemo(() => {
    if (!searchFilter.trim()) return matches;
    const q = searchFilter.toLowerCase();
    return matches.filter(
      (m) =>
        m.resolved_api.toLowerCase().includes(q) ||
        m.hash_hex.toLowerCase().includes(q) ||
        m.dll.toLowerCase().includes(q) ||
        m.algorithm.toLowerCase().includes(q) ||
        (m.address && m.address.toLowerCase().includes(q))
    );
  }, [matches, searchFilter]);

  const algorithmCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    matches.forEach((m) => {
      counts[m.algorithm] = (counts[m.algorithm] || 0) + 1;
    });
    return counts;
  }, [matches]);

  // Generate automated YARA signature based on detected hash constants
  const generatedYaraRule = useMemo(() => {
    const safeRuleName = `Detect_ApiHashing_${filename.replace(/[^a-zA-Z0-9_]/g, '_')}`;
    const stringRules = matches
      .map((m, idx) => {
        // Little endian hex format for 32-bit integer: 0x91afca54 -> { 54 ca af 91 }
        const clean = m.hash_hex.replace('0x', '').padStart(8, '0');
        const b0 = clean.substring(6, 8);
        const b1 = clean.substring(4, 6);
        const b2 = clean.substring(2, 4);
        const b3 = clean.substring(0, 2);
        return `        $hash_${idx + 1}_${m.resolved_api} = { ${b0} ${b1} ${b2} ${b3} } // ${m.algorithm}: ${m.dll}!${m.resolved_api}`;
      })
      .slice(0, 10)
      .join('\n');

    return `rule ${safeRuleName} {
    meta:
        description = "Automated detection of dynamic API hashing constants (${matches.length} APIs resolved)"
        author = "FileSanitizer Forensics Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        mitre_technique = "T1027.007"
        sample_filename = "${filename}"
    strings:
${stringRules || '        $hash_placeholder = { 54 ca af 91 }'}
    condition:
        uint16(0) == 0x5A4D and ${Math.min(matches.length, 2)} of them
}`;
  }, [matches, filename]);

  const handleCopyYara = () => {
    navigator.clipboard.writeText(generatedYaraRule);
    setCopiedYara(true);
    setTimeout(() => setCopiedYara(false), 2000);
  };

  const getSeverityStyle = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'high':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'medium':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="flex flex-col h-full bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
      {/* Header */}
      <div className="p-4 border-b border-slate-200 bg-slate-50/70 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-100/80 text-purple-700 rounded-lg">
            <Hash className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-semibold text-slate-900">API Hashing & Dynamic Resolution Inspector</h4>
              <span className="px-2 py-0.5 text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200 rounded">
                MITRE T1027.007
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Identified obfuscated Win32/Native APIs resolved dynamically through precomputed hashes in code.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowYaraModal(true)}
            className="px-3 py-1.5 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Generate YARA Rule
          </button>
        </div>
      </div>

      {/* Overview Stat Badges */}
      <div className="p-3 border-b border-slate-100 bg-white grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
          <span className="text-[10px] uppercase font-semibold text-slate-400 block">Total Hashes Resolved</span>
          <span className="text-lg font-bold text-slate-900 font-mono">{matches.length}</span>
        </div>
        <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
          <span className="text-[10px] uppercase font-semibold text-slate-400 block">Unique Libraries</span>
          <span className="text-lg font-bold text-purple-700 font-mono">
            {new Set(matches.map((m) => m.dll)).size}
          </span>
        </div>
        <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
          <span className="text-[10px] uppercase font-semibold text-slate-400 block">Active Algorithms</span>
          <div className="flex flex-wrap gap-1 mt-0.5">
            {Object.entries(algorithmCounts).map(([algo, count]) => (
              <span key={algo} className="px-1.5 py-0.5 bg-purple-100/60 text-purple-800 text-[10px] font-mono rounded">
                {algo}: {count}
              </span>
            ))}
          </div>
        </div>
        <div className="p-2.5 bg-rose-50/50 border border-rose-200 rounded-lg">
          <span className="text-[10px] uppercase font-semibold text-rose-600 block">Injection / Memory APIs</span>
          <span className="text-lg font-bold text-rose-700 font-mono">
            {matches.filter((m) => m.severity === 'critical').length}
          </span>
        </div>
      </div>

      {/* Search Toolbar */}
      <div className="p-3 border-b border-slate-100 bg-slate-50/40 flex items-center justify-between gap-3">
        <div className="relative w-72">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Filter by API, hash, library..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full pl-8 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-purple-500"
          />
        </div>
        <span className="text-xs text-slate-500 font-medium">
          Showing {filteredMatches.length} of {matches.length} resolved calls
        </span>
      </div>

      {/* Main Table */}
      <div className="flex-1 overflow-y-auto p-4">
        {filteredMatches.length === 0 ? (
          <div className="text-center py-12">
            <Hash className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <p className="text-sm font-medium text-slate-700">No dynamic API hashes detected</p>
            <p className="text-xs text-slate-400 mt-1">
              Disassembly instructions do not contain constant operands matching known ROR13, CRC32, or FNV-1a API hashes.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden border border-slate-200 rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 border-b border-slate-200 font-semibold uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-2.5 px-3">Resolved Function</th>
                  <th className="py-2.5 px-3">Target Library</th>
                  <th className="py-2.5 px-3">Hash Constant</th>
                  <th className="py-2.5 px-3">Algorithm</th>
                  <th className="py-2.5 px-3">Address</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredMatches.map((m, idx) => (
                  <tr key={idx} className="hover:bg-purple-50/30 transition-colors">
                    <td className="py-2.5 px-3 font-mono font-semibold text-slate-900">
                      {m.resolved_api}
                      <span className="block text-[10px] font-sans font-normal text-slate-500 mt-0.5">
                        {m.description}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-600">{m.dll}</td>
                    <td className="py-2.5 px-3 font-mono font-medium text-purple-700">{m.hash_hex}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-50 text-purple-700 border border-purple-200">
                        {m.algorithm}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-700">
                      {m.address || m.offset || 'N/A'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getSeverityStyle(
                          m.severity
                        )}`}
                      >
                        {m.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        {onOpenXrefs && (
                          <button
                            onClick={() => onOpenXrefs(m.resolved_api)}
                            className="px-2 py-1 text-[11px] font-medium text-blue-600 hover:bg-blue-50 rounded flex items-center gap-1 transition-colors"
                            title="Inspect XREFs for this API"
                          >
                            <Layers className="w-3 h-3" />
                            XREFs
                          </button>
                        )}
                        {onJumpToAddress && m.address && (
                          <button
                            onClick={() => onJumpToAddress(m.address!)}
                            className="px-2 py-1 text-[11px] font-medium text-slate-700 hover:bg-slate-100 rounded flex items-center gap-1 transition-colors"
                            title="Jump to instruction site"
                          >
                            <ExternalLink className="w-3 h-3" />
                            Jump
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* YARA Generation Modal */}
      {showYaraModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
          <div className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-2xl flex flex-col max-h-[85vh] animate-in fade-in zoom-in-95 duration-150">
            <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/70 rounded-t-xl">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-purple-600" />
                <h4 className="font-semibold text-slate-900 text-sm">Automated YARA Signature Generator</h4>
              </div>
              <button
                onClick={() => setShowYaraModal(false)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded"
              >
                ✕
              </button>
            </div>
            <div className="p-4 flex-1 overflow-y-auto">
              <p className="text-xs text-slate-500 mb-2">
                This rule matches the 32-bit little-endian API hash constants extracted from this binary sample.
              </p>
              <pre className="p-3 bg-slate-900 text-purple-200 rounded-lg text-xs font-mono overflow-x-auto leading-relaxed border border-slate-800">
                {generatedYaraRule}
              </pre>
            </div>
            <div className="p-3 border-t border-slate-200 bg-slate-50 flex items-center justify-end gap-2 rounded-b-xl">
              <button
                onClick={handleCopyYara}
                className="px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
              >
                {copiedYara ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedYara ? 'Copied YARA Rule' : 'Copy YARA Rule'}
              </button>
              <button
                onClick={() => setShowYaraModal(false)}
                className="px-3 py-1.5 bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 rounded-lg text-xs font-medium transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
