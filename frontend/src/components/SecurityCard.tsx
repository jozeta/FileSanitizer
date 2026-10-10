import React, { useState, useRef } from 'react';
import { Bug, Info, Code, ExternalLink, Activity, ShieldAlert, Tag, Clock } from 'lucide-react';
import {
  RiskAssessment,
  ClamAVScan,
  Finding,
  VirusTotalResult,
  HybridAnalysisResult,
  ThreatFoxResult,
  CirclHashlookupResult,
  MalwareBazaarResult,
  AlienVaultOTXResult,
  YaraResult,
  ExtractedCode,
  ReanalysisIntelDiff
} from '../types';
import { RiskBadge } from './RiskBadge';
import { getRiskColors } from '../utils/formatters';
import { GpsCoordinateBadge } from './GpsCoordinateBadge';

interface SecurityCardProps {
  risk?: RiskAssessment;
  clamav?: ClamAVScan;
  findings?: Finding[];
  jobHashes?: Record<string, string>;
  virustotal?: VirusTotalResult;
  hybrid_analysis?: HybridAnalysisResult;
  threatfox?: ThreatFoxResult;
  malwarebazaar?: MalwareBazaarResult;
  circl?: CirclHashlookupResult;
  alienvault_otx?: AlienVaultOTXResult;
  yara?: YaraResult;
  extractedCode?: ExtractedCode | null;
  onViewCode?: () => void;
  disabledChecks?: string[];
  reanalysisIntelDiff?: ReanalysisIntelDiff;
}

export const SecurityCard: React.FC<SecurityCardProps> = ({
  risk,
  clamav,
  findings = [],
  jobHashes,
  virustotal,
  hybrid_analysis,
  threatfox,
  malwarebazaar,
  circl,
  alienvault_otx,
  yara,
  extractedCode,
  onViewCode,
  disabledChecks = [],
  reanalysisIntelDiff,
}) => {
  const level = risk?.level || 'CLEAN';
  const colors = getRiskColors(level);
  const sha256 = jobHashes?.sha256 || '';
  const vtLink = virustotal?.web_link || (sha256 ? `https://www.virustotal.com/gui/file/${sha256}` : '');
  const haLink = hybrid_analysis?.report_url || (sha256 ? `https://hybrid-analysis.com/sample/${sha256}` : '');
  const tfLink = threatfox?.search_url || (sha256 ? `https://threatfox.abuse.ch/browse.php?search=ioc%3A${sha256}` : '');
  const mbLink = malwarebazaar?.search_url || (sha256 ? `https://bazaar.abuse.ch/sample/${sha256}/` : '');
  const circlLink = circl?.search_url || (sha256 ? `https://hashlookup.circl.lu/search/${sha256}` : '');
  const otxLink = alienvault_otx?.search_url || (sha256 ? `https://otx.alienvault.com/indicator/file/${sha256}` : '');
  const dlpFindings = findings.filter(f => f.category === 'dlp');

  // Floating hover state for YARA rule matches
  const [hoveredYaraInfo, setHoveredYaraInfo] = useState<{
    title: string;
    subtitle?: string;
    matches: Array<{
      ruleName: string;
      identifier: string;
      description?: string;
      strings?: any[];
      severity?: string;
    }>;
    x: number;
    y: number;
  } | null>(null);

  // Floating hover state for Risk Score Breakdown
  const [hoveredRiskInfo, setHoveredRiskInfo] = useState<{
    x: number;
    y: number;
  } | null>(null);

  const closeTimeoutRef = useRef<any>(null);
  const closeRiskTimeoutRef = useRef<any>(null);

  return (
    <div className="space-y-6 relative">
      {/* Re-Analysis Threat Intelligence Delta Highlight Banner */}
      {reanalysisIntelDiff && reanalysisIntelDiff.has_new_intelligence && (
        <div className="p-4 sm:p-5 rounded-3xl bg-gradient-to-r from-amber-50 via-rose-50 to-orange-50 border border-amber-300 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="w-10 h-10 rounded-2xl bg-amber-500 text-white flex items-center justify-center font-bold text-lg shadow-sm shrink-0">
              ⚡
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wider text-amber-900 bg-amber-200/80 px-2.5 py-0.5 rounded-full border border-amber-300">
                  Re-Analysis Threat Intel Update
                </span>
                {reanalysisIntelDiff.previous_scan_date && (
                  <span className="text-xs text-slate-500 font-medium">
                    New telemetry detected compared to previous submission on {new Date(reanalysisIntelDiff.previous_scan_date).toLocaleDateString()}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2 mt-2">
                {reanalysisIntelDiff.summary_labels.map((label, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1.5 text-xs font-bold px-3 py-1 rounded-xl bg-white border border-rose-200 text-rose-700 shadow-2xs"
                  >
                    <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                    {label}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Risk Overview Card */}
      <div className={`rounded-3xl border ${colors.border} ${colors.bg} p-6 sm:p-8 shadow-sm transition-all`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-200/60">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-slate-500 block mb-1">
              Overall Security Status
            </span>
            <div className="flex flex-wrap items-center gap-3">
              {/* Interactive Risk Status & Score with Hover Breakdown */}
              <div
                className="relative inline-flex items-center gap-2.5 cursor-pointer group"
                onMouseEnter={(e) => {
                  if (closeRiskTimeoutRef.current) {
                    clearTimeout(closeRiskTimeoutRef.current);
                    closeRiskTimeoutRef.current = null;
                  }
                  const rect = e.currentTarget.getBoundingClientRect();
                  const popupWidth = Math.min(540, window.innerWidth - 32);
                  const left = Math.max(16, Math.min(rect.left, window.innerWidth - popupWidth - 16));
                  const top = Math.min(rect.bottom + 8, window.innerHeight - 480);
                  setHoveredRiskInfo({
                    x: left,
                    y: Math.max(16, top),
                  });
                }}
                onMouseLeave={() => {
                  closeRiskTimeoutRef.current = setTimeout(() => {
                    setHoveredRiskInfo(null);
                  }, 300);
                }}
                title="Hover or click for detailed explainable risk subscore breakdown"
              >
                <RiskBadge level={level} size="lg" />
                {risk && (
                  <span className="text-sm font-mono text-slate-700 font-semibold flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-white/70 hover:bg-white border border-slate-200/80 shadow-2xs transition-all group-hover:border-blue-400 group-hover:text-blue-700">
                    <span>Risk Score: {risk.score}/100</span>
                    <Info className="w-3.5 h-3.5 text-slate-400 group-hover:text-blue-500 transition-colors" />
                  </span>
                )}
              </div>

              {yara && yara.matches_count > 0 && (
                <span
                  onMouseEnter={(e) => {
                    if (closeTimeoutRef.current) {
                      clearTimeout(closeTimeoutRef.current);
                      closeTimeoutRef.current = null;
                    }
                    const rect = e.currentTarget.getBoundingClientRect();
                    const popupWidth = Math.min(520, window.innerWidth - 32);
                    const left = Math.max(16, Math.min(rect.left, window.innerWidth - popupWidth - 16));
                    const top = Math.min(rect.bottom + 8, window.innerHeight - 480);
                    setHoveredYaraInfo({
                      title: `${yara.matches_count} YARA Rule Match${yara.matches_count > 1 ? 'es' : ''}`,
                      subtitle: 'Signatures matched across file binary structures and streams',
                      matches: yara.matches.map((m) => ({
                        ruleName: m.rule_name || m.identifier || 'Rule',
                        identifier: m.identifier || m.rule_name || 'YARA',
                        description: m.description,
                        strings: m.strings || [],
                        severity: m.severity || 'HIGH',
                      })),
                      x: left,
                      y: Math.max(16, top),
                    });
                  }}
                  onMouseLeave={() => {
                    closeTimeoutRef.current = setTimeout(() => {
                      setHoveredYaraInfo(null);
                    }, 300);
                  }}
                  className="px-2.5 py-0.5 bg-purple-100 hover:bg-purple-200 text-purple-800 border border-purple-200 text-xs font-semibold rounded-full flex items-center gap-1 cursor-pointer transition-colors"
                >
                  <span>🎯</span>
                  <span>{yara.matches_count} YARA Match{yara.matches_count > 1 ? 'es' : ''}</span>
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Extracted Code Button */}
            {extractedCode && onViewCode && (
              <button
                onClick={onViewCode}
                className="bg-white/95 hover:bg-slate-900 hover:text-white text-slate-900 border border-slate-300 rounded-2xl p-2.5 px-4 flex items-center gap-2.5 shadow-sm transition-all cursor-pointer font-semibold text-xs"
              >
                <Code className="w-4 h-4 text-cyan-600" />
                <span>Inspect {extractedCode.type.toUpperCase()} Code</span>
              </button>
            )}

            {/* Antivirus Pill */}
            {clamav && !disabledChecks?.includes('check_clamav') && (
              <div className="bg-white/90 border border-slate-200 rounded-2xl p-3 sm:px-4 flex items-center gap-3">
                <div className="p-2 rounded-xl bg-slate-100 text-slate-700">
                  <Bug className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono text-slate-500">Antivirus (ClamAV)</div>
                  <div className="text-sm font-bold flex items-center gap-1.5">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        clamav?.status === 'CLEAN'
                          ? 'bg-emerald-500'
                          : clamav?.status === 'MALICIOUS'
                          ? 'bg-rose-600 animate-pulse'
                          : clamav?.status === 'UNAVAILABLE'
                          ? 'bg-slate-400'
                          : 'bg-amber-500'
                      }`}
                    />
                    <span className={clamav?.status === 'MALICIOUS' ? 'text-rose-700' : 'text-slate-900'}>
                      {clamav?.status || 'UNAVAILABLE'}
                    </span>
                  </div>
                </div>
              </div>
            )}
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

      {/* Threat Intelligence & VirusTotal Integration Card */}
      {virustotal && !disabledChecks?.includes('check_virustotal') && (
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <span className="p-1.5 bg-blue-50 text-blue-600 rounded-lg">
              <Activity className="w-4 h-4" />
            </span>
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold">
              VirusTotal Threat Intelligence
            </h4>
            {Boolean(reanalysisIntelDiff?.new_vt_detections && reanalysisIntelDiff.new_vt_detections > 0) && (
              <span className="px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-300 text-[10px] font-bold animate-pulse">
                ⚡ +{reanalysisIntelDiff?.new_vt_detections} New Detections
              </span>
            )}
          </div>

          {vtLink && (
            <a
              href={vtLink}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-100 hover:bg-slate-200 text-blue-700 hover:text-blue-800 text-xs font-semibold rounded-lg border border-slate-200 transition-colors"
            >
              <span>Inspect Hash on VirusTotal</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>

        {virustotal?.queried && virustotal.found ? (
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-slate-400 block mb-0.5">Detections Ratio</span>
                <span className={`font-bold text-sm ${virustotal.positives && virustotal.positives > 0 ? 'text-rose-600' : 'text-emerald-600'}`}>
                  {virustotal.positives || 0} / {virustotal.total_engines || 0} Engines Flagged
                </span>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-slate-400 block mb-0.5">Community Reputation</span>
                <span className="font-bold text-slate-800">{virustotal.reputation || 0}</span>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-slate-400 block mb-0.5">Target SHA-256</span>
                <span className="text-slate-600 truncate block">{sha256}</span>
              </div>
            </div>

            {/* Enriched Metadata: Classification, Category, Submissions, File Type */}
            {(virustotal.suggested_threat_label || virustotal.threat_category || virustotal.type_description || virustotal.times_submitted !== undefined) && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                {virustotal.suggested_threat_label && (
                  <div className="p-3 bg-rose-50/70 rounded-xl border border-rose-100 sm:col-span-2">
                    <span className="text-rose-600 block mb-0.5 font-semibold flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> Suggested Threat Label
                    </span>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="font-bold text-rose-900 break-all text-sm">
                        {virustotal.suggested_threat_label}
                      </span>
                      {virustotal.threat_category && (
                        <span className="px-1.5 py-0.5 bg-rose-200 text-rose-800 rounded text-[10px] uppercase font-bold shrink-0">
                          {virustotal.threat_category}
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {virustotal.type_description && (
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                    <span className="text-slate-400 block mb-0.5">File Classification</span>
                    <span className="font-semibold text-slate-800">{virustotal.type_description}</span>
                  </div>
                )}
                {virustotal.times_submitted !== undefined && (
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                    <span className="text-slate-400 block mb-0.5 flex items-center gap-1">
                      <Clock className="w-3 h-3" /> Historical Submissions
                    </span>
                    <span className="font-semibold text-slate-800">{virustotal.times_submitted} times</span>
                  </div>
                )}
              </div>
            )}

            {/* Tags */}
            {virustotal.tags && virustotal.tags.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1 mr-1">
                  <Tag className="w-3 h-3" /> VT Tags:
                </span>
                {virustotal.tags.map((tag, tIdx) => (
                  <span
                    key={tIdx}
                    className="px-2 py-0.5 bg-slate-100 text-slate-600 border border-slate-200 rounded-md font-mono text-[10px]"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            )}

            {/* Flagged Antivirus Engines Breakdown */}
            {virustotal.flagged_engines && virustotal.flagged_engines.length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-100">
                <span className="text-xs font-semibold text-slate-700 block mb-2">
                  Flagged Antivirus Engines ({virustotal.flagged_engines.length})
                </span>
                <div className="space-y-1.5">
                  {virustotal.flagged_engines.map((eng, eIdx) => (
                    <div
                      key={eIdx}
                      className="flex items-center justify-between p-2 bg-rose-50/50 rounded-lg border border-rose-100 text-xs font-mono"
                    >
                      <span className="font-bold text-slate-900">{eng.engine}</span>
                      <span className="text-rose-700 font-semibold truncate max-w-[260px] text-right">
                        {eng.result}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-slate-50 rounded-xl border border-slate-100 text-xs">
            <div>
              <span className="font-semibold text-slate-800 block">
                {virustotal?.configured ? 'No previous VirusTotal submission found.' : 'Direct VirusTotal Search Available'}
              </span>
              <span className="text-slate-500 font-mono text-[11px]">
                SHA-256: {sha256 || 'Unavailable'}
              </span>
            </div>
            {vtLink && (
              <a
                href={vtLink}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-600 hover:text-blue-800 font-medium underline flex items-center gap-1 shrink-0"
              >
                Search on VirusTotal ↗
              </a>
            )}
          </div>
        )}
      </div>
      )}

      {/* CrowdStrike Falcon Sandbox / Hybrid Analysis Integration Card */}
      {hybrid_analysis && !disabledChecks?.includes('check_crowdstrike') && (
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <span className="p-1.5 bg-orange-50 text-orange-600 rounded-lg text-base">
              🦅
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold flex items-center gap-1.5">
                  <span>CrowdStrike Falcon Sandbox / Hybrid Analysis</span>
                </h4>
                {Boolean(reanalysisIntelDiff?.new_crowdstrike_threat) && (
                  <span className="px-2 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-300 text-[10px] font-bold animate-pulse">
                    ⚡ New Threat Identified
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400">
                Automated malware detonation, threat score, malware families & MITRE ATT&CK telemetry
              </p>
            </div>
          </div>

          {haLink && (
            <a
              href={haLink}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1 bg-slate-100 hover:bg-slate-200 text-orange-700 hover:text-orange-800 text-xs font-semibold rounded-lg border border-slate-200 transition-colors"
            >
              <span>Inspect Sample on Hybrid Analysis</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>

        {hybrid_analysis && hybrid_analysis.configured && hybrid_analysis.status && !['NOT_CONFIGURED', 'UNKNOWN'].includes(hybrid_analysis.status) && hybrid_analysis.verdict !== 'no_results' && hybrid_analysis.verdict !== 'not_found' ? (
          <div className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              {/* Threat Score */}
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-slate-400 block mb-0.5">Threat Score</span>
                <span
                  className={`font-bold text-sm ${
                    (hybrid_analysis.threat_score || 0) >= 70
                      ? 'text-rose-600'
                      : (hybrid_analysis.threat_score || 0) >= 40
                      ? 'text-amber-600'
                      : 'text-emerald-600'
                  }`}
                >
                  {hybrid_analysis.threat_score !== undefined ? `${hybrid_analysis.threat_score} / 100` : '0 / 100'}
                  <span className="text-[11px] font-normal text-slate-500 ml-1">
                    {(hybrid_analysis.threat_score || 0) >= 70
                      ? '• Malicious'
                      : (hybrid_analysis.threat_score || 0) >= 40
                      ? '• Suspicious'
                      : '• Clean'}
                  </span>
                </span>
              </div>

              {/* Verdict */}
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-slate-400 block mb-0.5">Community Verdict</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span
                    className={`font-bold px-2 py-0.5 rounded text-[11px] uppercase ${
                      ['malicious', 'threat'].includes(hybrid_analysis.verdict?.toLowerCase() || '')
                        ? 'bg-rose-100 text-rose-800'
                        : ['suspicious'].includes(hybrid_analysis.verdict?.toLowerCase() || '')
                        ? 'bg-amber-100 text-amber-800'
                        : 'bg-emerald-100 text-emerald-800'
                    }`}
                  >
                    {hybrid_analysis.verdict || hybrid_analysis.status}
                  </span>
                </div>
              </div>

              {/* AV Detection Rate */}
              <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                <span className="text-slate-400 block mb-0.5">AV Multi-Scan Detection</span>
                <span className="font-bold text-slate-800 text-sm">
                  {hybrid_analysis.av_detect_rate !== undefined ? `${hybrid_analysis.av_detect_rate}%` : 'N/A'}
                </span>
              </div>
            </div>

            {/* Malware Family & Environment */}
            {(hybrid_analysis.malware_family || hybrid_analysis.environment) && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                {hybrid_analysis.malware_family && (
                  <div className="p-3 bg-rose-50/70 rounded-xl border border-rose-100">
                    <span className="text-rose-600 block mb-0.5 font-semibold flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> Malware Family
                    </span>
                    <span className="font-bold text-rose-900 text-sm">
                      {hybrid_analysis.malware_family}
                    </span>
                  </div>
                )}
                {hybrid_analysis.environment && (
                  <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                    <span className="text-slate-400 block mb-0.5">Sandbox Environment</span>
                    <span className="font-semibold text-slate-800">
                      {hybrid_analysis.environment}
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* MITRE ATT&CK Matrix Techniques */}
            {hybrid_analysis.mitre_attck && hybrid_analysis.mitre_attck.length > 0 && (
              <div className="pt-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1 mr-1">
                    <Tag className="w-3 h-3" /> MITRE ATT&CK:
                  </span>
                  {hybrid_analysis.mitre_attck.map((attckId, mIdx) => (
                    <a
                      key={mIdx}
                      href={`https://attack.mitre.org/techniques/${attckId.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2 py-0.5 bg-orange-50 text-orange-700 border border-orange-200 hover:bg-orange-100 rounded-md font-mono text-[10px] font-semibold transition-colors"
                      title={`View MITRE ATT&CK technique ${attckId}`}
                    >
                      {attckId} ↗
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 bg-slate-50 rounded-xl border border-slate-100 text-xs">
            <div>
              <span className="font-semibold text-slate-800 block">
                {hybrid_analysis?.configured
                  ? 'No automated Falcon Sandbox detonation report on record for this hash.'
                  : 'Hybrid Analysis Community API Key is not configured.'}
              </span>
              <span className="text-slate-500 font-mono text-[11px]">
                {hybrid_analysis?.configured
                  ? `SHA-256: ${sha256 || 'Unavailable'} (Click to inspect or submit to CrowdStrike Falcon Sandbox)`
                  : 'Add your free Hybrid Analysis API key in Settings to automatically query threat scores and detonation reports.'}
              </span>
            </div>
            {haLink && (
              <a
                href={haLink}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-orange-600 hover:text-orange-800 font-medium underline flex items-center gap-1 shrink-0"
              >
                Inspect on Hybrid Analysis ↗
              </a>
            )}
          </div>
        )}
      </div>
      )}

      {/* Multi-Source Threat Intelligence: Abuse.ch ThreatFox & CIRCL Hashlookup Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Abuse.ch ThreatFox Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <span className="p-1.5 bg-rose-50 text-rose-600 rounded-lg text-base">🦊</span>
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold">
                    Abuse.ch ThreatFox IOCs
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Community malware IOC database & threat indicator sharing
                  </p>
                </div>
              </div>
              {tfLink && (
                <a
                  href={tfLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-rose-700 hover:text-rose-800 text-[11px] font-semibold rounded-lg border border-slate-200 transition-colors"
                >
                  <span>ThreatFox</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>

            {threatfox && threatfox.status === 'MALICIOUS' ? (
              <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-rose-600 text-white rounded text-[10px] font-extrabold uppercase tracking-wider">
                    ⚠️ Malware IOC Hit
                  </span>
                  <span className="font-bold text-rose-900 text-xs">
                    {threatfox.malware || 'Malicious Indicator'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1 text-slate-700">
                  <div>
                    <span className="text-slate-400 block text-[10px]">Threat Type</span>
                    <span className="font-semibold text-rose-900">{threatfox.threat_type || 'Malware Indicator'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Confidence</span>
                    <span className="font-semibold text-rose-900">{threatfox.confidence || 100}%</span>
                  </div>
                </div>
              </div>
            ) : threatfox && threatfox.status === 'CLEAN' ? (
              <div className="p-3 bg-emerald-50/70 border border-emerald-200 rounded-xl flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                  <span className="font-semibold text-emerald-900">
                    No active malware IOC records found
                  </span>
                </div>
                <span className="text-emerald-700 text-[11px] font-mono font-medium">✓ Clean</span>
              </div>
            ) : (
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-600">
                <span className="font-semibold block mb-0.5">No IOC Records Found</span>
                <span className="text-[11px] text-slate-500">Hash is not listed in Abuse.ch ThreatFox IOC tracking database.</span>
              </div>
            )}
          </div>
        </div>

        {/* MalwareBazaar (Abuse.ch) Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <span className="p-1.5 bg-rose-50 text-rose-600 rounded-lg text-base">🦠</span>
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold">
                    MalwareBazaar (Abuse.ch)
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Community malware sample intelligence & family signatures
                  </p>
                </div>
              </div>
              {mbLink && (
                <a
                  href={mbLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-rose-700 hover:text-rose-800 text-[11px] font-semibold rounded-lg border border-slate-200 transition-colors"
                >
                  <span>MalwareBazaar</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>

            {malwarebazaar && malwarebazaar.status === 'MALICIOUS' ? (
              <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-rose-600 text-white rounded text-[10px] font-extrabold uppercase tracking-wider">
                    ⚠️ Malware Threat Hit
                  </span>
                  <span className="font-bold text-rose-900 text-xs">
                    {malwarebazaar.signature || 'Malware Sample'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1 text-slate-700">
                  <div>
                    <span className="text-slate-400 block text-[10px]">File Type</span>
                    <span className="font-semibold text-rose-900">{malwarebazaar.file_type || 'Binary'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">First Seen</span>
                    <span className="font-semibold text-slate-800 truncate block">{malwarebazaar.first_seen || 'Recorded'}</span>
                  </div>
                </div>
                {malwarebazaar.tags && malwarebazaar.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {malwarebazaar.tags.map((t, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 bg-rose-200/60 text-rose-900 rounded text-[10px] font-mono">
                        #{t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ) : malwarebazaar && malwarebazaar.status === 'CLEAN' ? (
              <div className="p-3 bg-emerald-50/70 border border-emerald-200 rounded-xl flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                  <span className="font-semibold text-emerald-900">
                    No active malware records in MalwareBazaar
                  </span>
                </div>
                <span className="text-emerald-700 text-[11px] font-mono font-medium">✓ Clean</span>
              </div>
            ) : (
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-600">
                <span className="font-semibold block mb-0.5">No Records Found</span>
                <span className="text-[11px] text-slate-500">Hash is not listed in Abuse.ch MalwareBazaar database.</span>
              </div>
            )}
          </div>
        </div>

        {/* CIRCL Hashlookup (NIST NSRL) Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <span className="p-1.5 bg-blue-50 text-blue-600 rounded-lg text-base">🏛️</span>
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold">
                    CIRCL Hashlookup (NSRL)
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    NIST National Software Reference Library verification
                  </p>
                </div>
              </div>
              {circlLink && (
                <a
                  href={circlLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-blue-700 hover:text-blue-800 text-[11px] font-semibold rounded-lg border border-slate-200 transition-colors"
                >
                  <span>CIRCL Search</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>

            {circl && (circl.status === 'BENIGN_KNOWN' || circl.is_nsrl) ? (
              <div className="p-3.5 bg-emerald-50 border border-emerald-200 rounded-xl space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-emerald-600 text-white rounded text-[10px] font-extrabold uppercase tracking-wider">
                    ✓ Verified Known Benign
                  </span>
                  <span className="font-bold text-emerald-900 text-xs truncate">
                    {circl.file_name || 'NSRL Reference File'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1 text-slate-700">
                  <div>
                    <span className="text-slate-400 block text-[10px]">Vendor / Publisher</span>
                    <span className="font-semibold text-emerald-900 truncate block">{circl.vendor || 'Standard Software'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Database Registry</span>
                    <span className="font-semibold text-emerald-900">NIST NSRL RDS</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-600">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="font-semibold text-slate-800">Unmatched in NIST NSRL Database</span>
                </div>
                <span className="text-[11px] text-slate-500 leading-relaxed block">
                  Typical for custom documents, user files, generated data, and proprietary software.
                </span>
              </div>
            )}
          </div>
        </div>

        {/* AlienVault OTX (Open Threat Exchange) Pulse Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <span className="p-1.5 bg-indigo-50 text-indigo-600 rounded-lg text-base">🛰️</span>
                <div>
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold">
                    AlienVault OTX
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Open Threat Exchange community pulses & APT attribution
                  </p>
                </div>
              </div>
              {otxLink && (
                <a
                  href={otxLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-indigo-700 hover:text-indigo-800 text-[11px] font-semibold rounded-lg border border-slate-200 transition-colors"
                >
                  <span>OTX Pulses</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>

            {alienvault_otx && alienvault_otx.pulse_count && alienvault_otx.pulse_count > 0 ? (
              <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl space-y-2">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-rose-600 text-white rounded text-[10px] font-extrabold uppercase tracking-wider">
                    ⚠️ {alienvault_otx.pulse_count} Threat Pulses
                  </span>
                  <span className="font-bold text-rose-900 text-xs truncate">
                    {alienvault_otx.pulse_names?.[0] || 'Active Threat Campaign'}
                  </span>
                </div>
                {alienvault_otx.tags && alienvault_otx.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {alienvault_otx.tags.slice(0, 4).map((tag, i) => (
                      <span key={i} className="px-2 py-0.5 bg-rose-100 text-rose-800 rounded text-[10px] font-mono">
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-3 bg-emerald-50/70 border border-emerald-200 rounded-xl flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                  <span className="font-semibold text-emerald-900">
                    No threat pulses reported in OTX
                  </span>
                </div>
                <span className="text-emerald-700 text-[11px] font-mono font-medium">✓ Clean</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ClamAV Engine Details */}
      {clamav && !disabledChecks?.includes('check_clamav') && (
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span>Antivirus Scanner Details</span>
              {Boolean(reanalysisIntelDiff?.new_clamav_signature) && (
                <span className="px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-300 text-[10px] font-bold animate-pulse">
                  ⚡ New Signature Match: {reanalysisIntelDiff?.new_clamav_signature}
                </span>
              )}
            </div>
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
      {/* DLP Sensitive Data & Leaked Credentials Banner */}
      {dlpFindings.length > 0 && (
        <div className="bg-amber-50/90 border border-amber-300 rounded-3xl p-6 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="p-2.5 bg-amber-600 text-white rounded-2xl shadow-sm text-base">🔑</span>
              <div>
                <h4 className="text-sm font-bold text-amber-950 flex items-center gap-2">
                  <span>Data Loss Prevention (DLP) Alert</span>
                  <span className="px-2 py-0.5 bg-amber-600 text-white text-[10px] font-extrabold uppercase rounded-full">
                    {dlpFindings.length} Leaked Secret{dlpFindings.length > 1 ? 's' : ''}
                  </span>
                </h4>
                <p className="text-xs text-amber-800">
                  Sensitive credentials, API keys, private keys, or financial cards were detected in file contents.
                </p>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
            {dlpFindings.map((df, idx) => (
              <div key={idx} className="p-3.5 bg-white border border-amber-200 rounded-2xl shadow-xs space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-900">{df.title}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-100 text-amber-800 rounded-md font-semibold">
                    {df.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-[11px] text-slate-600">{df.description}</p>
                {df.details?.redacted_samples && df.details.redacted_samples.length > 0 && (
                  <div className="pt-1 flex flex-wrap gap-1">
                    {df.details.redacted_samples.map((s: string, sIdx: number) => (
                      <span key={sIdx} className="px-2 py-0.5 bg-slate-100 border border-slate-200 text-slate-800 font-mono text-[10px] rounded-md font-bold">
                        {s}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detailed Findings Breakdown */}
      {findings.length > 0 && (
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-4">
            Security Findings Catalog ({findings.length})
          </h4>
          <div className="space-y-3">
            {findings.map((f, idx) => {
              const isCodeFinding =
                (f.category === 'macro' || f.category === 'javascript' || f.category === 'yara') &&
                Boolean(extractedCode);

              const isGpsFinding =
                f.details?.latitude !== undefined ||
                (f.category === 'metadata' && f.title.toLowerCase().includes('gps'));

              const gpsLat = f.details?.latitude;
              const gpsLon = f.details?.longitude;
              const gpsReadable = f.details?.readable;
              const gpsCity = f.details?.city;
              const gpsCountry = f.details?.country;
              const gpsLocation = f.details?.location_name;

              return (
                <div
                  key={idx}
                  className="p-3.5 bg-slate-50 hover:bg-slate-100/80 rounded-xl border border-slate-100 transition-colors"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2">
                      {f.category === 'yara' ? (
                        <span
                          onMouseEnter={(e) => {
                            if (closeTimeoutRef.current) {
                              clearTimeout(closeTimeoutRef.current);
                              closeTimeoutRef.current = null;
                            }
                            const rect = e.currentTarget.getBoundingClientRect();
                            const popupWidth = Math.min(520, window.innerWidth - 32);
                            const left = Math.max(16, Math.min(rect.left, window.innerWidth - popupWidth - 16));
                            const top = Math.min(rect.bottom + 8, window.innerHeight - 480);
                            setHoveredYaraInfo({
                              title: f.title,
                              subtitle: f.description,
                              matches: [
                                {
                                  ruleName: f.title,
                                  identifier: f.details?.rule_id || 'YARA Rule',
                                  description: f.description,
                                  strings: f.details?.strings || [],
                                  severity: f.severity?.toUpperCase(),
                                },
                              ],
                              x: left,
                              y: Math.max(16, top),
                            });
                          }}
                          onMouseLeave={() => {
                            closeTimeoutRef.current = setTimeout(() => {
                              setHoveredYaraInfo(null);
                            }, 300);
                          }}
                          className="text-sm font-semibold text-purple-900 bg-purple-50 hover:bg-purple-100 px-2 py-0.5 rounded-lg border border-purple-200 transition-colors cursor-pointer inline-flex items-center gap-1.5"
                        >
                          <span>🎯</span>
                          <span>{f.title}</span>
                          <span className="text-[10px] text-purple-600 font-mono">(Hover for matched bytes)</span>
                        </span>
                      ) : (
                        <span className="text-sm font-semibold text-slate-900">{f.title}</span>
                      )}
                      {isCodeFinding && onViewCode && (
                        <button
                          onClick={onViewCode}
                          className="px-2 py-0.5 bg-cyan-100 hover:bg-cyan-200 text-cyan-900 text-[11px] font-semibold rounded cursor-pointer transition-colors flex items-center gap-1"
                        >
                          <span>👁️</span>
                          View Code
                        </button>
                      )}
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold ${
                        f.severity === 'critical'
                          ? 'bg-rose-100 text-rose-800'
                          : f.severity === 'high'
                          ? 'bg-red-100 text-red-800'
                          : f.severity === 'medium'
                          ? 'bg-amber-100 text-amber-800'
                          : f.severity === 'low'
                          ? 'bg-slate-200 text-slate-800'
                          : 'bg-blue-100 text-blue-800'
                      }`}
                    >
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">{f.description}</p>

                  {/* Warninglist Detected Data Callout */}
                  {f.category === 'warninglist' && (f.details?.detected_value || f.details?.rule_name) && (
                    <div className="mt-2.5 p-2.5 bg-amber-50/90 border border-amber-200 rounded-xl flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-semibold text-amber-900 flex items-center gap-1.5 shrink-0">
                        <span>🔍</span>
                        <span>Detected Sensitive Data:</span>
                      </span>
                      {f.details?.detected_value && (
                        <span className="font-mono bg-white px-2.5 py-0.5 rounded-lg border border-amber-300 text-rose-700 font-bold select-all break-all shadow-xs">
                          {f.details.detected_value}
                        </span>
                      )}
                      {f.details?.rule_name && (
                        <span className="text-amber-800 text-[11px] ml-auto font-medium">
                          Rule: <strong className="font-semibold">{f.details.rule_name}</strong>
                        </span>
                      )}
                    </div>
                  )}

                  {/* GPS Hover Location Badge */}
                  {isGpsFinding && (gpsLat !== undefined || gpsReadable) && (
                    <div className="mt-2.5 pt-2 border-t border-slate-200/60 flex flex-wrap items-center gap-2">
                      <span className="text-[11px] font-mono text-slate-500 font-medium">Geolocation:</span>
                      <GpsCoordinateBadge
                        latitude={gpsLat}
                        longitude={gpsLon}
                        readableCoordinates={gpsReadable}
                        initialCity={gpsCity}
                        initialCountry={gpsCountry}
                        locationName={gpsLocation}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Floating YARA Match Details Popover on Top of Everything */}
      {hoveredYaraInfo && (
        <div
          onMouseEnter={() => {
            if (closeTimeoutRef.current) {
              clearTimeout(closeTimeoutRef.current);
              closeTimeoutRef.current = null;
            }
          }}
          onMouseLeave={() => {
            closeTimeoutRef.current = setTimeout(() => {
              setHoveredYaraInfo(null);
            }, 300);
          }}
          style={{
            position: 'fixed',
            left: hoveredYaraInfo.x,
            top: hoveredYaraInfo.y,
            zIndex: 9999,
          }}
          className="w-[560px] max-w-[92vw] max-h-[520px] flex flex-col bg-white text-slate-800 rounded-2xl p-4 shadow-2xl border border-purple-200 pointer-events-auto"
        >
          <div className="flex items-center justify-between pb-2 border-b border-slate-100 shrink-0">
            <span className="text-[10px] font-mono uppercase tracking-wider text-purple-700 font-bold flex items-center gap-1.5">
              <span>🎯</span> YARA Rule Match Details
            </span>
            <button
              type="button"
              onClick={() => setHoveredYaraInfo(null)}
              className="w-6 h-6 flex items-center justify-center text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors text-xs font-bold"
            >
              ✕
            </button>
          </div>

          <div className="py-2 shrink-0">
            <h5 className="font-bold text-sm text-slate-900">{hoveredYaraInfo.title}</h5>
            {hoveredYaraInfo.subtitle && (
              <p className="text-xs text-slate-500 mt-0.5">{hoveredYaraInfo.subtitle}</p>
            )}
          </div>

          <div className="border-t border-slate-100 pt-2 flex-1 overflow-y-auto space-y-3 pr-1">
            {hoveredYaraInfo.matches.map((m, mIdx) => (
              <div key={mIdx} className="bg-slate-50 p-3 rounded-xl border border-slate-200 text-xs">
                <div className="flex items-center justify-between text-purple-700 font-mono text-[11px] mb-1">
                  <span className="font-bold text-slate-900">{m.ruleName}</span>
                  <div className="flex items-center gap-1.5">
                    <span className="px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 text-[10px]">
                      {m.identifier}
                    </span>
                    {m.severity && (
                      <span className="px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-bold">
                        {m.severity}
                      </span>
                    )}
                  </div>
                </div>
                {m.description && m.description !== m.ruleName && (
                  <p className="text-slate-600 text-[11px] mb-2">{m.description}</p>
                )}

                {m.strings && m.strings.length > 0 ? (
                  <div>
                    <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold block mb-1.5">
                      Matched Byte Sequences ({m.strings.length}):
                    </span>
                    <div className="space-y-1.5">
                      {m.strings.map((s: any, sIdx: number) => (
                        <div key={sIdx} className="bg-white p-2.5 rounded-lg border border-slate-200 font-mono text-[11px]">
                          <div className="flex items-center justify-between text-purple-600 text-[10px] mb-1 font-semibold">
                            <span>{s.identifier || `$s${sIdx}`}</span>
                            {s.offset !== undefined && <span>0x{Number(s.offset).toString(16)}</span>}
                          </div>
                          <div className="text-slate-800 break-all select-all font-mono leading-relaxed">{s.matched_data || (s as any).data || JSON.stringify(s)}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 italic">Signature matched structure or binary headers.</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Explainable Risk Score Breakdown Popover */}
      {hoveredRiskInfo && risk && (
        <div
          style={{
            position: 'fixed',
            top: hoveredRiskInfo.y,
            left: hoveredRiskInfo.x,
            maxWidth: '540px',
            width: '92vw',
            zIndex: 9999,
          }}
          onMouseEnter={() => {
            if (closeRiskTimeoutRef.current) {
              clearTimeout(closeRiskTimeoutRef.current);
              closeRiskTimeoutRef.current = null;
            }
          }}
          onMouseLeave={() => {
            closeRiskTimeoutRef.current = setTimeout(() => {
              setHoveredRiskInfo(null);
            }, 300);
          }}
          className="bg-white/95 backdrop-blur-md border border-slate-300 shadow-2xl rounded-2xl p-5 text-slate-800 animate-in fade-in zoom-in-95 duration-150"
        >
          {/* Popover Header */}
          <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-200">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-slate-900 uppercase tracking-wider font-mono">
                  Explainable Risk Score Breakdown
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-800 font-mono">
                  {risk.score}/100
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Itemization of security factors and weighted subscores determining the <strong>{level}</strong> verdict.
              </p>
            </div>
            <RiskBadge level={level} size="sm" />
          </div>

          {/* Formula rationale */}
          {risk.calculation_formula && (
            <div className="mt-3 p-2.5 bg-slate-50 rounded-xl border border-slate-200 text-[11px] font-mono text-slate-600 flex flex-wrap items-center justify-between gap-2">
              <span className="text-slate-400 uppercase text-[10px] font-bold">Calculation Formula:</span>
              <span className="text-blue-700 font-semibold">{risk.calculation_formula}</span>
            </div>
          )}

          {/* Itemized Subscores */}
          <div className="mt-3.5 space-y-2 max-h-[300px] overflow-y-auto pr-1">
            <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider block">
              Contributing Factors &amp; Subscores ({risk.breakdown?.length || 0})
            </span>

            {risk.breakdown && risk.breakdown.length > 0 ? (
              <div className="space-y-1.5">
                {risk.breakdown.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 bg-slate-50 hover:bg-slate-100/80 rounded-xl border border-slate-200/80 transition-colors flex items-start justify-between gap-3 text-xs"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-800">{item.factor}</span>
                        <span className="text-[9px] uppercase px-1.5 py-0.5 rounded font-mono font-bold bg-slate-200 text-slate-700">
                          {item.category}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-0.5 line-clamp-2">{item.reason}</p>
                    </div>
                    <span
                      className={`shrink-0 font-mono font-bold text-xs px-2 py-0.5 rounded-lg ${
                        (item.subscore ?? item.points ?? 0) >= 40
                          ? 'bg-rose-100 text-rose-800 border border-rose-200'
                          : (item.subscore ?? item.points ?? 0) >= 20
                          ? 'bg-amber-100 text-amber-800 border border-amber-200'
                          : 'bg-blue-100 text-blue-800 border border-blue-200'
                      }`}
                    >
                      +{(item.subscore ?? item.points ?? 0)} pts
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl text-center">
                <span className="text-xs text-emerald-800 font-medium block">
                  ✓ Clean baseline: No active scripts, exploits, malicious signatures, or structural anomalies detected.
                </span>
                <span className="block text-[10px] text-emerald-600 mt-1 font-mono">0 penalty subscores applied</span>
              </div>
            )}
          </div>

          {/* Footer Summary */}
          <div className="mt-4 pt-3 border-t border-slate-200 flex items-center justify-between text-xs font-semibold">
            <span className="text-slate-500">Aggregate Calculated Score:</span>
            <span className="font-mono text-slate-900 bg-slate-100 px-2.5 py-1 rounded-lg border border-slate-200">
              {risk.score} / 100 points
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
