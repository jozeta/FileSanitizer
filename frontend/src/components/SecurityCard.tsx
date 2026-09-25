import React from 'react';
import { Bug, Info } from 'lucide-react';
import { RiskAssessment, ClamAVScan, Finding } from '../types';
import { RiskBadge } from './RiskBadge';
import { getRiskColors } from '../utils/formatters';

interface SecurityCardProps {
  risk?: RiskAssessment;
  clamav?: ClamAVScan;
  findings?: Finding[];
}

export const SecurityCard: React.FC<SecurityCardProps> = ({ risk, clamav, findings = [] }) => {
  const level = risk?.level || 'CLEAN';
  const colors = getRiskColors(level);

  return (
    <div className="space-y-6">
      {/* Risk Overview Card */}
      <div className={`rounded-3xl border ${colors.border} ${colors.bg} p-6 sm:p-8 shadow-sm transition-all`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-200/60">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-slate-500 block mb-1">
              Overall Security Status
            </span>
            <div className="flex items-center gap-3">
              <RiskBadge level={level} size="lg" />
              {risk && (
                <span className="text-sm font-mono text-slate-500">
                  Risk Score: {risk.score}/100
                </span>
              )}
            </div>
          </div>

          {/* Antivirus Pill */}
          <div className="bg-white/90 border border-slate-200 rounded-2xl p-3 sm:px-4 flex items-center gap-3">
            <div className="p-2 rounded-xl bg-slate-100 text-slate-700">
              <Bug className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono text-slate-500">Antivirus (ClamAV)</div>
              <div className="text-sm font-bold flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${
                  clamav?.status === 'CLEAN' ? 'bg-emerald-500' :
                  clamav?.status === 'MALICIOUS' ? 'bg-rose-600 animate-pulse' :
                  clamav?.status === 'UNAVAILABLE' ? 'bg-slate-400' : 'bg-amber-500'
                }`} />
                <span className={clamav?.status === 'MALICIOUS' ? 'text-rose-700' : 'text-slate-900'}>
                  {clamav?.status || 'UNAVAILABLE'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Explainable Reasons */}
        <div className="py-5">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-600 mb-3">
            Analysis Findings & Explanations:
          </h4>
          {risk?.reasons && risk.reasons.length > 0 ? (
            <ul className="space-y-2">
              {risk.reasons.map((reason, idx) => (
                <li key={idx} className="text-sm font-medium text-slate-800 flex items-start gap-2">
                  <span className="leading-relaxed">{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-600">No active threats or suspicious anomalies detected.</p>
          )}
        </div>

        {/* Recommendation Box */}
        {risk?.recommendation && (
          <div className="mt-2 bg-white/90 border border-slate-200 rounded-2xl p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-xl bg-blue-50 text-blue-600 shrink-0">
                <Info className="w-4 h-4" />
              </div>
              <div>
                <h5 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-1">
                  Security Recommendation
                </h5>
                <p className="text-sm text-slate-800 leading-relaxed font-normal">
                  {risk.recommendation}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ClamAV Engine Details */}
      {clamav && (
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-3 flex items-center justify-between">
            <span>Antivirus Scanner Details</span>
            <span className="font-mono text-[11px] text-slate-400">Daemon protocol</span>
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
              <span className="text-slate-400 block mb-0.5">Scanner</span>
              <span className="font-semibold text-slate-800">{clamav.scanner}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
              <span className="text-slate-400 block mb-0.5">Engine</span>
              <span className="font-semibold text-slate-800">{clamav.engine_version}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
              <span className="text-slate-400 block mb-0.5">Signatures</span>
              <span className="font-semibold text-slate-800 truncate block">{clamav.signature_db}</span>
            </div>
            <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
              <span className="text-slate-400 block mb-0.5">Scan Status</span>
              <span className={`font-semibold ${clamav.status === 'CLEAN' ? 'text-emerald-700' : clamav.status === 'MALICIOUS' ? 'text-rose-700' : 'text-slate-700'}`}>
                {clamav.status}
              </span>
            </div>
          </div>
          <p className="text-[11px] text-slate-400 mt-3 italic">
            * Note: A clean antivirus scan verifies that no known signatures were matched; it does not guarantee the absence of unknown exploits or zero-days.
          </p>
        </div>
      )}

      {/* Detailed Findings Breakdown */}
      {findings.length > 0 && (
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-4">
            Security Findings Catalog ({findings.length})
          </h4>
          <div className="space-y-3">
            {findings.map((f, idx) => (
              <div
                key={idx}
                className="p-3.5 bg-slate-50 hover:bg-slate-100/80 rounded-xl border border-slate-100 transition-colors"
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-sm font-semibold text-slate-900">{f.title}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
                    f.severity === 'critical' ? 'bg-rose-100 text-rose-800' :
                    f.severity === 'high' ? 'bg-red-100 text-red-800' :
                    f.severity === 'medium' ? 'bg-amber-100 text-amber-800' :
                    f.severity === 'low' ? 'bg-slate-200 text-slate-800' :
                    'bg-blue-100 text-blue-800'
                  }`}>
                    {f.severity}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
