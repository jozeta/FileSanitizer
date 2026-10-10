import React, { useState } from 'react';
import {
  Clock,
  CheckCircle2,
  AlertTriangle,
  Network,
  Cpu,
  Layers,
  Search,
  Activity,
  ShieldCheck,
  Globe,
  Sliders,
  Terminal,
} from 'lucide-react';
import { JobTelemetry, StepTiming } from '../types';

interface JobDiagnosticsCardProps {
  telemetry?: JobTelemetry;
  fileSize: number;
  mimeType: string;
  category: string;
  filename: string;
}

export const JobDiagnosticsCard: React.FC<JobDiagnosticsCardProps> = ({
  telemetry,
  fileSize,
  mimeType,
  category,
  filename,
}) => {
  const [filterQuery, setFilterQuery] = useState('');
  const [activeSubTab, setActiveSubTab] = useState<'timeline' | 'checks' | 'network' | 'logs'>('timeline');

  if (!telemetry) {
    return (
      <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-3xl">
        <Activity className="w-10 h-10 text-slate-400 mx-auto mb-3 animate-spin" />
        <h4 className="text-sm font-bold text-slate-700">Telemetry In Progress</h4>
        <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
          Analysis telemetry and execution metrics are recorded during pipeline execution and will finalize when all scan steps complete.
        </p>
      </div>
    );
  }

  const {
    started_at,
    completed_at,
    total_duration_ms = 0,
    steps = [],
    checks_executed = [],
    disabled_checks = [],
    network_telemetry,
    pipeline_errors = [],
  } = telemetry;

  const totalDurationFormatted =
    total_duration_ms > 1000
      ? `${(total_duration_ms / 1000).toFixed(2)}s`
      : `${total_duration_ms.toFixed(0)}ms`;

  const maxStepDuration = Math.max(...steps.map((s) => s.duration_ms || 1), 1);

  const filteredChecks = checks_executed.filter((chk) =>
    chk.toLowerCase().includes(filterQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Overview Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="p-4 bg-gradient-to-br from-indigo-50 to-blue-50/50 border border-indigo-200/80 rounded-2xl shadow-2xs">
          <div className="flex items-center gap-2 text-indigo-600 mb-1.5">
            <Clock className="w-4 h-4" />
            <span className="text-[10px] uppercase font-bold tracking-wider">Total Pipeline Time</span>
          </div>
          <div className="text-2xl font-black text-slate-900 font-mono">{totalDurationFormatted}</div>
          <span className="text-[11px] text-slate-500 mt-0.5 block">
            {steps.length} execution stages
          </span>
        </div>

        <div className="p-4 bg-gradient-to-br from-emerald-50 to-teal-50/50 border border-emerald-200/80 rounded-2xl shadow-2xs">
          <div className="flex items-center gap-2 text-emerald-600 mb-1.5">
            <ShieldCheck className="w-4 h-4" />
            <span className="text-[10px] uppercase font-bold tracking-wider">Security Checks</span>
          </div>
          <div className="text-2xl font-black text-slate-900 font-mono">
            {checks_executed.length}
          </div>
          <span className="text-[11px] text-slate-500 mt-0.5 block">
            {disabled_checks.length > 0 ? `${disabled_checks.length} checks disabled` : 'All rules active'}
          </span>
        </div>

        <div className="p-4 bg-gradient-to-br from-cyan-50 to-sky-50/50 border border-cyan-200/80 rounded-2xl shadow-2xs">
          <div className="flex items-center gap-2 text-cyan-600 mb-1.5">
            <Globe className="w-4 h-4" />
            <span className="text-[10px] uppercase font-bold tracking-wider">External Lookups</span>
          </div>
          <div className="text-2xl font-black text-slate-900 font-mono">
            {network_telemetry?.external_lookups_count || 0}
          </div>
          <span className="text-[11px] text-slate-500 mt-0.5 block truncate" title={(network_telemetry?.services_contacted || []).join(', ')}>
            {network_telemetry?.services_contacted?.length || 0} services queried
          </span>
        </div>

        <div className="p-4 bg-gradient-to-br from-purple-50 to-violet-50/50 border border-purple-200/80 rounded-2xl shadow-2xs">
          <div className="flex items-center gap-2 text-purple-600 mb-1.5">
            <Cpu className="w-4 h-4" />
            <span className="text-[10px] uppercase font-bold tracking-wider">Target Payload</span>
          </div>
          <div className="text-lg font-black text-slate-900 font-mono truncate" title={filename}>
            {(fileSize / 1024).toFixed(1)} KB
          </div>
          <span className="text-[11px] text-slate-500 mt-0.5 block font-mono truncate">
            {category.toUpperCase()} • {mimeType.split('/')[1] || mimeType}
          </span>
        </div>
      </div>

      {/* Main Tabbed Container */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-7 shadow-xs">
        {/* Navigation Sub-Tabs */}
        <div className="flex border-b border-slate-200 gap-2 mb-6 overflow-x-auto">
          <button
            onClick={() => setActiveSubTab('timeline')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeSubTab === 'timeline'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Execution Waterfall &amp; Step Timings</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {steps.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('checks')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeSubTab === 'checks'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Executed Checks Matrix</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {checks_executed.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('network')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeSubTab === 'network'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Network className="w-4 h-4" />
            <span>Network &amp; Threat Intel Telemetry</span>
            <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200/80 text-slate-700 font-mono">
              {network_telemetry?.external_lookups_count || 0}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('logs')}
            className={`px-4 py-2.5 text-xs font-bold rounded-t-xl transition-all flex items-center gap-2 cursor-pointer ${
              activeSubTab === 'logs'
                ? 'bg-blue-50 text-blue-700 border-b-2 border-blue-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Diagnostics Logs &amp; Audit</span>
            {pipeline_errors.length > 0 && (
              <span className="px-1.5 py-0.5 text-[10px] rounded-full bg-rose-100 text-rose-700 font-mono font-bold">
                {pipeline_errors.length}
              </span>
            )}
          </button>
        </div>

        {/* Sub-Tab 1: Execution Waterfall */}
        {activeSubTab === 'timeline' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-bold text-slate-900">Pipeline Stages &amp; Latency Waterfall</h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Detailed execution profile showing millisecond timing for each pipeline analysis stage.
                </p>
              </div>
              <span className="text-xs font-mono font-bold text-slate-600 bg-slate-100 px-3 py-1 rounded-xl border border-slate-200">
                Total: {totalDurationFormatted}
              </span>
            </div>

            <div className="space-y-3 pt-2">
              {steps.map((st: StepTiming) => {
                const pct = total_duration_ms > 0 ? (st.duration_ms / total_duration_ms) * 100 : 0;
                const barWidth = Math.max(2, (st.duration_ms / maxStepDuration) * 100);

                return (
                  <div
                    key={st.step}
                    className="p-3.5 bg-slate-50 hover:bg-slate-100/70 border border-slate-200/80 rounded-2xl transition-all"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2.5">
                        <span className="w-6 h-6 rounded-lg bg-white border border-slate-200 font-mono text-xs font-bold flex items-center justify-center text-slate-700 shadow-2xs">
                          {st.step}
                        </span>
                        <span className="text-xs font-bold text-slate-900">{st.name}</span>
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md ${
                            st.status === 'success'
                              ? 'bg-emerald-100 text-emerald-800'
                              : st.status === 'skipped'
                              ? 'bg-slate-200 text-slate-600'
                              : 'bg-rose-100 text-rose-800'
                          }`}
                        >
                          {st.status}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 font-mono text-xs">
                        <span className="text-slate-400 text-[11px]">{pct.toFixed(1)}%</span>
                        <span className="font-bold text-slate-800 bg-white px-2 py-0.5 rounded border border-slate-200">
                          {st.duration_ms.toFixed(1)} ms
                        </span>
                      </div>
                    </div>

                    {/* Horizontal Waterfall Bar */}
                    <div className="w-full bg-slate-200/70 rounded-full h-2 overflow-hidden mb-2">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          st.status === 'skipped'
                            ? 'bg-slate-400'
                            : st.duration_ms > 500
                            ? 'bg-amber-500'
                            : 'bg-indigo-600'
                        }`}
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>

                    {st.details && (
                      <p className="text-[11px] text-slate-500 font-mono truncate pl-8">
                        • {st.details}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Sub-Tab 2: Executed Checks Matrix */}
        {activeSubTab === 'checks' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 className="text-sm font-bold text-slate-900">Security Checks &amp; Inspection Rules</h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Full inventory of active forensic scanners, heuristic checks, and format engines executed.
                </p>
              </div>

              <div className="relative min-w-[220px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter checks..."
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs focus:outline-hidden focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-2">
              {filteredChecks.map((chk, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-50/80 border border-slate-200/80 rounded-xl flex items-center justify-between text-xs transition-colors hover:bg-slate-100"
                >
                  <div className="flex items-center gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span className="font-medium text-slate-800">{chk}</span>
                  </div>
                  <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-mono">
                    PASS
                  </span>
                </div>
              ))}
            </div>

            {disabled_checks.length > 0 && (
              <div className="mt-5 p-4 bg-amber-50/60 border border-amber-200 rounded-2xl">
                <span className="text-xs font-bold text-amber-800 block mb-2 flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-amber-600" />
                  Checks Disabled via Policy / Settings ({disabled_checks.length}):
                </span>
                <div className="flex flex-wrap gap-2">
                  {disabled_checks.map((dc, i) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 rounded-lg bg-white border border-amber-300 text-amber-900 font-mono text-[11px]"
                    >
                      {dc}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Sub-Tab 3: Network & Threat Intel */}
        {activeSubTab === 'network' && (
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-bold text-slate-900">External Threat Intelligence Lookups</h4>
              <p className="text-xs text-slate-500 mt-0.5">
                Audit trail of outbound API queries performed against security databases and threat repositories.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 pt-2">
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <span className="text-[10px] font-bold uppercase text-slate-400 block mb-1">
                  External Lookups Performed
                </span>
                <span className="text-2xl font-black text-slate-900 font-mono">
                  {network_telemetry?.external_lookups_count || 0}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">Outbound API calls</span>
              </div>

              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <span className="text-[10px] font-bold uppercase text-slate-400 block mb-1">
                  Extracted URLs Inspected
                </span>
                <span className="text-2xl font-black text-slate-900 font-mono">
                  {network_telemetry?.urls_inspected || 0}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">Probed for reputation &amp; SSL</span>
              </div>

              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200">
                <span className="text-[10px] font-bold uppercase text-slate-400 block mb-1">
                  Threat Platforms Contacted
                </span>
                <span className="text-2xl font-black text-slate-900 font-mono">
                  {network_telemetry?.services_contacted?.length || 0}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">Active intelligence feeds</span>
              </div>
            </div>

            <div className="mt-4">
              <span className="text-xs font-bold text-slate-800 block mb-2.5">Queried Intelligence Feeds:</span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {(network_telemetry?.services_contacted || []).map((srv, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-white border border-slate-200 rounded-xl flex items-center justify-between text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                      <span className="font-semibold text-slate-800">{srv}</span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 font-bold">ACTIVE LOOKUP</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Sub-Tab 4: Diagnostics Logs */}
        {activeSubTab === 'logs' && (
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-bold text-slate-900">Job Pipeline Audit &amp; Event Timestamps</h4>
              <p className="text-xs text-slate-500 mt-0.5">
                Exact UTC initiation, completion timestamps, and non-fatal pipeline error logs.
              </p>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 text-slate-800 rounded-2xl font-mono text-xs space-y-2">
              <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                <span className="text-slate-500">Pipeline Started:</span>
                <span className="text-emerald-700 font-semibold">{started_at || 'N/A'}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                <span className="text-slate-500">Pipeline Completed:</span>
                <span className="text-emerald-700 font-semibold">{completed_at || 'N/A'}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                <span className="text-slate-500">Elapsed Execution:</span>
                <span className="text-indigo-700 font-bold">{totalDurationFormatted} ({total_duration_ms} ms)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Execution Status:</span>
                <span className={pipeline_errors.length > 0 ? 'text-amber-700 font-semibold' : 'text-emerald-700 font-semibold'}>
                  {pipeline_errors.length > 0 ? `Completed with ${pipeline_errors.length} non-fatal warning(s)` : 'Completed Cleanly (Zero Errors)'}
                </span>
              </div>
            </div>

            {pipeline_errors.length > 0 ? (
              <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl">
                <span className="text-xs font-bold text-rose-800 block mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                  Non-Fatal Warnings &amp; Handled Pipeline Exceptions:
                </span>
                <ul className="text-xs text-rose-700 space-y-1 font-mono list-disc pl-5">
                  {pipeline_errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>All pipeline steps and forensic modules executed cleanly without timeouts or unhandled exceptions.</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
