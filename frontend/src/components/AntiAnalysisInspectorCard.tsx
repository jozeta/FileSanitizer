import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Cpu,
  Clock,
  EyeOff,
  Crosshair,
  Lock,
  Layers,
  ExternalLink
} from 'lucide-react';
import { AntiAnalysisInfo } from '../types';

interface AntiAnalysisInspectorCardProps {
  antiAnalysis?: AntiAnalysisInfo;
  filename?: string;
  category?: string;
}

export const AntiAnalysisInspectorCard: React.FC<AntiAnalysisInspectorCardProps> = ({
  antiAnalysis,
  filename = 'file',
  category: _category = 'artifact'
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const techniques = antiAnalysis?.techniques || [];
  const hasEvasion = Boolean(antiAnalysis?.evasion_detected && techniques.length > 0);

  // Available categories
  const categories = useMemo(() => {
    const cats = new Set<string>();
    techniques.forEach((t) => {
      if (t.category) cats.add(t.category);
    });
    return Array.from(cats);
  }, [techniques]);

  const filteredTechniques = useMemo(() => {
    return techniques.filter((t) => {
      const matchesCat = selectedCategory === 'all' || t.category === selectedCategory;
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        (t.evidence && t.evidence.toLowerCase().includes(q)) ||
        (t.mitre_id && t.mitre_id.toLowerCase().includes(q));
      return matchesCat && matchesSearch;
    });
  }, [techniques, selectedCategory, searchQuery]);

  const getSeverityBadge = (sev: string) => {
    const s = (sev || 'info').toLowerCase();
    if (s === 'critical') return 'bg-rose-100 text-rose-800 border-rose-300';
    if (s === 'high') return 'bg-amber-100 text-amber-800 border-amber-300';
    if (s === 'medium') return 'bg-yellow-100 text-yellow-800 border-yellow-300';
    return 'bg-blue-100 text-blue-800 border-blue-200';
  };

  const getCategoryIcon = (catName?: string) => {
    const c = (catName || '').toLowerCase();
    if (c.includes('debug')) return <EyeOff className="w-3.5 h-3.5 text-rose-600" />;
    if (c.includes('vm') || c.includes('sandbox')) return <Cpu className="w-3.5 h-3.5 text-amber-600" />;
    if (c.includes('sleep') || c.includes('timing') || c.includes('time')) return <Clock className="w-3.5 h-3.5 text-indigo-600" />;
    if (c.includes('tool')) return <Crosshair className="w-3.5 h-3.5 text-purple-600" />;
    if (c.includes('defense') || c.includes('evasion')) return <Lock className="w-3.5 h-3.5 text-red-600" />;
    return <Layers className="w-3.5 h-3.5 text-slate-600" />;
  };

  if (!hasEvasion) {
    return (
      <div className="p-6 bg-white border border-slate-200 rounded-3xl shadow-sm">
        <div className="flex items-center gap-3 text-emerald-800">
          <div className="p-2 bg-emerald-50 border border-emerald-200 rounded-xl">
            <ShieldCheck className="w-5 h-5 text-emerald-600" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-slate-800">Anti-Analysis & Evasion Verification Clean</h4>
            <p className="text-xs text-slate-500 mt-0.5">
              No anti-debugging traps, sandbox sleep acceleration, hypervisor detection, or environment guardrails identified in {filename}.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 bg-white border border-slate-200 rounded-3xl shadow-sm space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 bg-rose-50/70 border border-rose-200 rounded-2xl">
        <div className="flex items-start gap-3">
          <div className="p-2.5 bg-rose-100 border border-rose-300 rounded-xl shrink-0 mt-0.5">
            <ShieldAlert className="w-6 h-6 text-rose-600" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base font-bold text-rose-950">
                Anti-Analysis & Defense Evasion Behaviors Detected
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-600 text-white uppercase tracking-wider">
                {antiAnalysis?.highest_severity?.toUpperCase() || 'CRITICAL'} RISK
              </span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-white text-rose-900 border border-rose-300">
                Confidence: {antiAnalysis?.confidence || 'HIGH'}
              </span>
            </div>
            <p className="text-xs text-rose-800 mt-1 leading-relaxed">
              {antiAnalysis?.summary || `${techniques.length} defense evasion and anti-analysis triggers were identified designed to hinder sandboxes and automated debuggers.`}
            </p>
          </div>
        </div>

        {/* MITRE Tags */}
        <div className="flex flex-wrap md:flex-col gap-1.5 shrink-0">
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-white border border-rose-300 text-rose-900">
            <span>MITRE T1497</span>
            <span className="text-[9px] text-slate-500">(Virtualization Evasion)</span>
          </span>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-white border border-rose-300 text-rose-900">
            <span>MITRE T1622</span>
            <span className="text-[9px] text-slate-500">(Debugger Evasion)</span>
          </span>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-white border border-rose-300 text-rose-900">
            <span>MITRE T1027</span>
            <span className="text-[9px] text-slate-500">(Obfuscated Evasion)</span>
          </span>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Category Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 scrollbar-thin">
          <button
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors cursor-pointer shrink-0 border ${
              selectedCategory === 'all'
                ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200'
            }`}
          >
            All Categories ({techniques.length})
          </button>
          {categories.map((cat) => {
            const count = techniques.filter((t) => t.category === cat).length;
            const isSelected = selectedCategory === cat;
            return (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors cursor-pointer shrink-0 flex items-center gap-1.5 border ${
                  isSelected
                    ? 'bg-indigo-600 text-white border-indigo-600 shadow-xs'
                    : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {getCategoryIcon(cat)}
                <span>{cat}</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${isSelected ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-700'}`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search Input */}
        <div className="relative min-w-[220px]">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search anti-analysis techniques..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white"
          />
        </div>
      </div>

      {/* Techniques Table / Cards */}
      <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white shadow-2xs">
        <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-50 text-[10px] uppercase font-semibold text-slate-500 border-b border-slate-200 sticky top-0 z-10">
              <tr>
                <th className="py-2.5 px-4 w-40">Category</th>
                <th className="py-2.5 px-4 w-60">Technique / Indicator</th>
                <th className="py-2.5 px-4">Behavioral Description & Evidence</th>
                <th className="py-2.5 px-4 w-28 text-center">MITRE ATT&CK</th>
                <th className="py-2.5 px-4 w-24 text-center">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-800 font-sans">
              {filteredTechniques.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-400 italic">
                    No anti-analysis techniques matched your filter criteria.
                  </td>
                </tr>
              ) : (
                filteredTechniques.map((tech, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-700">
                      <div className="flex items-center gap-1.5">
                        {getCategoryIcon(tech.category)}
                        <span className="truncate">{tech.category || 'General'}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-900">
                      <div className="font-mono text-xs">{tech.name}</div>
                    </td>
                    <td className="py-3 px-4">
                      <p className="text-xs text-slate-700 leading-relaxed">{tech.description}</p>
                      {tech.evidence && (
                        <div className="mt-1.5 flex items-center gap-1.5 font-mono text-[11px] text-slate-600 bg-slate-50 p-1.5 rounded-lg border border-slate-200/80">
                          <span className="text-slate-400 uppercase text-[9px] font-bold">Evidence:</span>
                          <span className="text-rose-950 truncate font-semibold">{tech.evidence}</span>
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-center">
                      {tech.mitre_id ? (
                        <a
                          href={`https://attack.mitre.org/techniques/${tech.mitre_id.replace(/\./g, '/')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 px-2 py-0.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 rounded text-[10px] font-mono font-bold border border-indigo-200 transition-colors"
                          title={`View MITRE ATT&CK technique ${tech.mitre_id}`}
                        >
                          <span>{tech.mitre_id}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ) : (
                        <span className="text-slate-400 font-mono text-[10px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityBadge(tech.severity)}`}>
                        {tech.severity || 'high'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
