import React, { useState } from 'react';
import { MitreAttackItem } from '../types';
import { ShieldAlert, Search, ExternalLink, Download } from 'lucide-react';

interface AttackNavigatorCardProps {
  mitreAttack?: MitreAttackItem[];
  jobId?: string;
}

export const AttackNavigatorCard: React.FC<AttackNavigatorCardProps> = ({ mitreAttack = [], jobId }) => {
  const [selectedTactic, setSelectedTactic] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  if (!mitreAttack || mitreAttack.length === 0) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <ShieldAlert className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No MITRE ATT&CK techniques mapped for this file.</p>
      </div>
    );
  }

  // Group by Tactics
  const tacticsMap: Record<string, MitreAttackItem[]> = {};
  mitreAttack.forEach((item) => {
    const tac = item.tactic_name || 'Execution';
    if (!tacticsMap[tac]) {
      tacticsMap[tac] = [];
    }
    tacticsMap[tac].push(item);
  });

  const tacticNames = Object.keys(tacticsMap);

  // Filter
  const filteredItems = mitreAttack.filter((item) => {
    const matchesTactic = selectedTactic === 'ALL' || item.tactic_name === selectedTactic;
    const matchesSearch =
      searchQuery === '' ||
      item.technique_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.technique_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.evidence.some((e) => e.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesTactic && matchesSearch;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'HIGH':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'MEDIUM':
        return 'bg-yellow-50 text-yellow-800 border-yellow-200';
      default:
        return 'bg-blue-50 text-blue-700 border-blue-200';
    }
  };

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm mb-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-indigo-50 text-indigo-600 rounded-2xl shrink-0 border border-indigo-100">
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                MITRE ATT&CK Enterprise Matrix Mapping
              </h3>
              <span className="text-xs bg-indigo-100 text-indigo-800 border border-indigo-200 px-2.5 py-0.5 rounded-full font-mono font-semibold">
                {mitreAttack.length} Techniques Mapped
              </span>
            </div>
            <p className="text-xs text-slate-500 font-normal">
              Correlated adversarial tactics and techniques identified across static indicators, YARA rules, and behavioral signatures.
            </p>
          </div>
        </div>

        {/* Actions & Search */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 w-full lg:w-auto">
          {jobId && (
            <div className="flex items-center gap-2">
              <a
                href={`/api/jobs/${jobId}/attack-navigator`}
                download
                className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 transition-colors whitespace-nowrap shadow-xs"
                title="Download official MITRE ATT&CK Navigator v4.5 JSON layer for this job"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Navigator Layer</span>
              </a>
              <a
                href={`/api/jobs/${jobId}/stix-export`}
                download
                className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 transition-colors whitespace-nowrap shadow-xs"
                title="Export OASIS STIX 2.1 Incident Response & Threat Bundle"
              >
                <Download className="w-3.5 h-3.5" />
                <span>STIX 2.1 Bundle</span>
              </a>
            </div>
          )}
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search technique or evidence..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="text-xs pl-9 pr-3 py-2 rounded-xl border border-slate-200 bg-slate-50 text-slate-900 placeholder:text-slate-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 w-full transition-all"
            />
          </div>
        </div>
      </div>

      {/* Tactics Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
        <button
          onClick={() => setSelectedTactic('ALL')}
          className={`text-xs px-3.5 py-1.5 rounded-xl font-semibold whitespace-nowrap transition-all cursor-pointer ${
            selectedTactic === 'ALL'
              ? 'bg-slate-900 text-white shadow-xs'
              : 'bg-slate-100 text-slate-600 hover:text-slate-900 hover:bg-slate-200 border border-slate-200/60'
          }`}
        >
          All Tactics ({mitreAttack.length})
        </button>
        {tacticNames.map((tac) => (
          <button
            key={tac}
            onClick={() => setSelectedTactic(tac)}
            className={`text-xs px-3.5 py-1.5 rounded-xl font-semibold whitespace-nowrap transition-all cursor-pointer ${
              selectedTactic === tac
                ? 'bg-indigo-600 text-white shadow-xs'
                : 'bg-slate-100 text-slate-600 hover:text-slate-900 hover:bg-slate-200 border border-slate-200/60'
            }`}
          >
            {tac} ({tacticsMap[tac].length})
          </button>
        ))}
      </div>

      {/* Grid of Techniques */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredItems.map((item, idx) => (
          <div
            key={`${item.technique_id}-${idx}`}
            className="p-4 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50/50 hover:border-indigo-300 transition-all shadow-2xs hover:shadow-sm flex flex-col justify-between space-y-3"
          >
            <div>
              <div className="flex items-start justify-between gap-2 mb-2">
                <span className="font-mono text-xs font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-md border border-indigo-100">
                  {item.technique_id}
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded-md border font-bold uppercase tracking-wider ${getSeverityBadge(item.severity)}`}>
                  {item.severity}
                </span>
              </div>
              <h4 className="font-semibold text-xs text-slate-900 mb-1.5">
                {item.technique_name}
              </h4>
              <p className="text-xs text-slate-600 leading-relaxed">
                {item.description}
              </p>
            </div>

            <div className="space-y-3 pt-2">
              {/* Evidence chips */}
              {item.evidence && item.evidence.length > 0 && (
                <div className="bg-slate-50/80 border border-slate-100 rounded-xl p-2.5 space-y-1.5">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                    Matched Evidence
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {item.evidence.map((ev, evIdx) => (
                      <span
                        key={evIdx}
                        className="text-[11px] px-2 py-0.5 rounded-md bg-white border border-slate-200 text-slate-800 font-medium max-w-full truncate shadow-2xs"
                        title={ev}
                      >
                        {ev}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Footer link to MITRE ATT&CK */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-100 text-[11px]">
                <span className="text-slate-500 font-medium">
                  {item.tactic_name} ({item.tactic_id})
                </span>
                <a
                  href={item.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-indigo-600 hover:text-indigo-800 font-semibold"
                >
                  <span>MITRE Spec</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
