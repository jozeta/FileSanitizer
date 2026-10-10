import React, { useState } from 'react';
import { ExtensionTriageInfo } from '../types';
import {
  Puzzle,
  ShieldAlert,
  ShieldCheck,
  Code,
  FileText,
  Eye,
  AlertTriangle,
  Lock,
  Terminal,
  Users,
  Star,
  ExternalLink,
  CheckCircle2,
  Globe,
  Award,
  BadgeCheck,
  Download
} from 'lucide-react';

interface ExtensionTriageCardProps {
  extensionInfo: ExtensionTriageInfo;
}

export const ExtensionTriageCard: React.FC<ExtensionTriageCardProps> = ({ extensionInfo }) => {
  const [activeTab, setActiveTab] = useState<'permissions' | 'scripts' | 'content_scripts' | 'csp'>('permissions');

  const {
    name,
    version,
    manifest_version,
    description,
    risk_score,
    risk_level,
    permissions,
    background,
    content_scripts,
    csp,
    js_findings,
    risk_flags,
    summary,
    store_intelligence,
    is_webstore_signed,
    verified_item_id,
    author,
    copyright_notice
  } = extensionInfo;

  const storeIntel = store_intelligence;

  const getRiskBadge = () => {
    switch (risk_level) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'HIGH RISK':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'MEDIUM RISK':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'LOW RISK':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    }
  };

  const getReputationBadge = (verdict?: string) => {
    switch (verdict) {
      case 'VERIFIED_AND_POPULAR':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'ESTABLISHED_COMMUNITY':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      case 'MODERATE_REPUTATION':
        return 'bg-slate-100 text-slate-800 border-slate-300';
      case 'UNLISTED_OR_SIDELOADED':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      default:
        return 'bg-amber-100 text-amber-800 border-amber-300';
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden mb-6">
      {/* Header */}
      <div className="px-6 py-4 bg-gradient-to-r from-indigo-50/80 via-slate-50 to-white border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-indigo-100/70 text-indigo-700 rounded-lg">
            <Puzzle className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-slate-800">
                {name || 'Browser Extension Package'}
              </h3>
              <span className="text-xs px-2 py-0.5 rounded font-mono font-medium bg-slate-100 text-slate-600 border border-slate-200">
                v{version}
              </span>
              <span className="text-xs px-2 py-0.5 rounded font-mono font-medium bg-indigo-50 text-indigo-700 border border-indigo-200">
                Manifest V{manifest_version || 3}
              </span>
              {is_webstore_signed && (
                <span className="inline-flex items-center text-xs px-2 py-0.5 rounded font-medium bg-emerald-50 text-emerald-700 border border-emerald-200" title={`Verified Store Package ID: ${verified_item_id || 'Present'}`}>
                  <BadgeCheck className="w-3.5 h-3.5 mr-1 text-emerald-600" />
                  Web Store Signed
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">
              {description || 'Chrome / Edge browser extension package (.crx)'}
            </p>
          </div>
        </div>

        {/* Risk Badge */}
        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-[11px] text-slate-500 font-medium block">Risk Score</span>
            <span className="text-base font-bold text-slate-800 font-mono">{risk_score}/100</span>
          </div>
          <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border ${getRiskBadge()}`}>
            {risk_level === 'CLEAN' ? (
              <ShieldCheck className="w-4 h-4 mr-1 text-emerald-600" />
            ) : (
              <ShieldAlert className="w-4 h-4 mr-1" />
            )}
            {risk_level}
          </span>
        </div>
      </div>

      {/* Summary Banner */}
      {summary && (
        <div className="px-6 py-3 bg-slate-50 border-b border-slate-200 text-xs text-slate-700">
          <span className="font-semibold text-slate-900">Summary: </span>
          {summary}
        </div>
      )}

      {/* Store Intelligence & Community Reputation */}
      {storeIntel && (
        <div className="px-6 py-4 bg-gradient-to-r from-indigo-50/50 via-white to-blue-50/40 border-b border-slate-200">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
            <div className="flex items-center gap-2">
              <span className="p-1.5 bg-indigo-100 text-indigo-700 rounded-lg">
                <Globe className="w-4 h-4" />
              </span>
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  {storeIntel.store_name || 'Chrome Web Store'} Intelligence &amp; Community Metrics
                </h4>
                <span className="text-[11px] text-slate-500 font-mono">
                  ID: {storeIntel.extension_id}
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {storeIntel.reputation_verdict && (
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getReputationBadge(storeIntel.reputation_verdict)}`}>
                  <Award className="w-3.5 h-3.5 mr-1" />
                  Reputation: {storeIntel.reputation_verdict.replace(/_/g, ' ')}
                </span>
              )}
              {storeIntel.google_esb_allowlist && (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                  Google ESB: Verified
                </span>
              )}
              {storeIntel.featured_badge && (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200">
                  <Star className="w-3.5 h-3.5 mr-1 text-amber-500 fill-amber-400" />
                  Featured Publisher
                </span>
              )}
              {storeIntel.store_url && (
                <a
                  href={storeIntel.store_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded-lg border border-indigo-200 transition-colors"
                >
                  <span>Store Page</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
            <div className="bg-white p-2.5 rounded-xl border border-slate-200/80 shadow-2xs">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-0.5">Active Users &amp; Downloads</span>
              <div className="flex items-center gap-1.5 font-bold text-slate-800 text-sm">
                <Users className="w-4 h-4 text-indigo-600" />
                <span>{storeIntel.users_count || (storeIntel.downloads_count ? `${storeIntel.downloads_count.toLocaleString()}+ users` : 'Unlisted / Private')}</span>
              </div>
              {storeIntel.downloads_count && (
                <span className="text-[11px] text-slate-500 font-mono flex items-center gap-1 mt-0.5">
                  <Download className="w-3 h-3 text-slate-400" />
                  {storeIntel.downloads_count.toLocaleString()} downloads
                </span>
              )}
            </div>

            <div className="bg-white p-2.5 rounded-xl border border-slate-200/80 shadow-2xs">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-0.5">Community Rating</span>
              <div className="flex items-center gap-1.5 font-bold text-slate-800 text-sm">
                <Star className="w-4 h-4 text-amber-500 fill-amber-400" />
                <span>{storeIntel.rating ? `${storeIntel.rating} / 5.0` : 'No rating'}</span>
                {storeIntel.reviews_count && (
                  <span className="text-[11px] font-normal text-slate-500 font-mono">({storeIntel.reviews_count})</span>
                )}
              </div>
              <span className="text-[10px] text-slate-500 block mt-0.5">Verified User Reviews</span>
            </div>

            <div className="bg-white p-2.5 rounded-xl border border-slate-200/80 shadow-2xs">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-0.5">Reputation Score</span>
              <div className="flex items-center gap-1.5 font-bold text-slate-800 text-sm">
                <Award className="w-4 h-4 text-indigo-600" />
                <span>{storeIntel.reputation_score !== undefined ? `${storeIntel.reputation_score} / 100` : 'N/A'}</span>
              </div>
              <span className="text-[10px] text-slate-500 block mt-0.5">Trust &amp; Community Metric</span>
            </div>

            <div className="bg-white p-2.5 rounded-xl border border-slate-200/80 shadow-2xs">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-0.5">Author / Publisher</span>
              <span className="font-semibold text-slate-800 truncate block text-xs" title={storeIntel.developer_owner || author || 'Unknown'}>
                {storeIntel.developer_owner || author || 'Unknown'}
              </span>
              {(copyright_notice || author) && (
                <span className="text-[10px] text-slate-500 truncate block mt-0.5" title={copyright_notice || author}>
                  {copyright_notice || `Author: ${author}`}
                </span>
              )}
            </div>

            <div className="bg-white p-2.5 rounded-xl border border-slate-200/80 shadow-2xs">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-0.5">Last Store Update</span>
              <span className="font-semibold text-slate-800 block text-xs">
                {storeIntel.last_update_date || 'N/A'}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">
                {storeIntel.store_version ? `Store Version: v${storeIntel.store_version}` : 'Version tracked'}
              </span>
            </div>
          </div>

          {storeIntel.reputation_summary && (
            <div className="mt-3 px-3 py-2 bg-indigo-50/70 border border-indigo-100 rounded-lg text-xs text-indigo-900 flex items-center justify-between">
              <span>
                <strong className="font-semibold">Reputation Analysis: </strong>
                {storeIntel.reputation_summary}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Risk Flags */}
      {risk_flags && risk_flags.length > 0 && (
        <div className="px-6 py-3 bg-red-50/70 border-b border-red-200 space-y-1.5">
          {risk_flags.map((flag, idx) => (
            <div key={idx} className="flex items-start gap-2 text-xs text-red-900">
              <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold">{flag.title}: </span>
                <span className="text-red-800">{flag.description}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="px-6 border-b border-slate-200 bg-white flex space-x-6">
        <button
          onClick={() => setActiveTab('permissions')}
          className={`py-3 text-xs font-semibold border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'permissions'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}
        >
          <Lock className="w-4 h-4" />
          Permissions ({permissions.critical.length + permissions.high.length + permissions.medium.length + permissions.low.length})
        </button>

        <button
          onClick={() => setActiveTab('scripts')}
          className={`py-3 text-xs font-semibold border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'scripts'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}
        >
          <Code className="w-4 h-4" />
          Security Heuristics ({js_findings.length})
        </button>

        <button
          onClick={() => setActiveTab('content_scripts')}
          className={`py-3 text-xs font-semibold border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'content_scripts'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}
        >
          <Eye className="w-4 h-4" />
          Content Scripts &amp; Workers ({content_scripts.length})
        </button>

        <button
          onClick={() => setActiveTab('csp')}
          className={`py-3 text-xs font-semibold border-b-2 flex items-center gap-1.5 transition-colors ${
            activeTab === 'csp'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}
        >
          <FileText className="w-4 h-4" />
          Content Security Policy (CSP)
        </button>
      </div>

      {/* Tab Contents */}
      <div className="p-6">
        {/* Tab 1: Permissions */}
        {activeTab === 'permissions' && (
          <div className="space-y-5">
            {/* Critical Permissions */}
            {permissions.critical.length > 0 && (
              <div className="border border-red-200 rounded-lg overflow-hidden">
                <div className="bg-red-50/80 px-4 py-2 border-b border-red-200 flex items-center justify-between">
                  <span className="text-xs font-bold text-red-900 uppercase tracking-wide">
                    Critical Risk Permissions ({permissions.critical.length})
                  </span>
                  <span className="text-[11px] font-semibold text-red-700">Broad browser / traffic takeover risk</span>
                </div>
                <div className="divide-y divide-red-100">
                  {permissions.critical.map((p, i) => (
                    <div key={i} className="p-3 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                      <span className="font-mono font-bold text-red-700 bg-red-50 px-2 py-0.5 rounded border border-red-200 inline-block w-fit">
                        {p.permission}
                      </span>
                      <span className="text-slate-600">{p.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* High Permissions */}
            {permissions.high.length > 0 && (
              <div className="border border-amber-200 rounded-lg overflow-hidden">
                <div className="bg-amber-50/80 px-4 py-2 border-b border-amber-200 flex items-center justify-between">
                  <span className="text-xs font-bold text-amber-900 uppercase tracking-wide">
                    High Risk Permissions ({permissions.high.length})
                  </span>
                  <span className="text-[11px] font-semibold text-amber-700">User privacy &amp; local inspection capabilities</span>
                </div>
                <div className="divide-y divide-amber-100">
                  {permissions.high.map((p, i) => (
                    <div key={i} className="p-3 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                      <span className="font-mono font-bold text-amber-800 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 inline-block w-fit">
                        {p.permission}
                      </span>
                      <span className="text-slate-600">{p.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Medium & Low Permissions */}
            {(permissions.medium.length > 0 || permissions.low.length > 0) && (
              <div className="border border-slate-200 rounded-lg overflow-hidden">
                <div className="bg-slate-50 px-4 py-2 border-b border-slate-200">
                  <span className="text-xs font-bold text-slate-700 uppercase tracking-wide">
                    Standard &amp; Low Risk Permissions ({permissions.medium.length + permissions.low.length})
                  </span>
                </div>
                <div className="p-3 bg-white flex flex-wrap gap-2 text-xs">
                  {permissions.medium.concat(permissions.low).map((p, i) => (
                    <span key={i} className="inline-flex items-center px-2.5 py-1 rounded bg-slate-100 text-slate-700 border border-slate-200 font-mono text-[11px]" title={p.description}>
                      {p.permission}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Host Permissions Pattern */}
            {permissions.host_permissions.length > 0 && (
              <div className="border border-slate-200 rounded-lg p-4 bg-slate-50/50">
                <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block mb-2">
                  Requested Host Permissions / Website URL Scopes:
                </span>
                <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                  {permissions.host_permissions.map((hp, i) => (
                    <span key={i} className={`px-2 py-0.5 rounded border ${
                      hp === '<all_urls>' || hp === '*://*/*'
                        ? 'bg-red-100 text-red-800 border-red-300 font-bold'
                        : 'bg-white text-slate-700 border-slate-200'
                    }`}>
                      {hp}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: JavaScript Heuristic Findings */}
        {activeTab === 'scripts' && (
          <div className="space-y-4">
            {js_findings.length > 0 ? (
              <div className="border border-slate-200 rounded-lg overflow-hidden">
                <table className="min-w-full divide-y divide-slate-200 text-left text-xs">
                  <thead className="bg-slate-50 text-slate-600 font-semibold uppercase tracking-wider text-[11px]">
                    <tr>
                      <th className="px-4 py-2.5">Severity</th>
                      <th className="px-4 py-2.5">Finding Title</th>
                      <th className="px-4 py-2.5">File</th>
                      <th className="px-4 py-2.5">MITRE ATT&amp;CK</th>
                      <th className="px-4 py-2.5">Snippet Preview</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {js_findings.map((jf, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/60">
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            jf.severity === 'CRITICAL' ? 'bg-red-100 text-red-800 border border-red-200' :
                            jf.severity === 'HIGH' ? 'bg-orange-100 text-orange-800 border border-orange-200' :
                            jf.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-800 border border-amber-200' :
                            'bg-slate-100 text-slate-700 border border-slate-200'
                          }`}>
                            {jf.severity}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 font-medium text-slate-800">
                          {jf.title}
                          {jf.occurrences > 1 && (
                            <span className="ml-1 text-[10px] text-slate-500 font-normal">
                              ({jf.occurrences}x)
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-slate-600">{jf.file}</td>
                        <td className="px-4 py-2.5 font-mono text-indigo-600 font-semibold">{jf.mitre}</td>
                        <td className="px-4 py-2.5 font-mono text-slate-700 max-w-xs truncate bg-slate-50/50">
                          <code>{jf.snippet}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-center py-8 text-slate-500 text-xs">
                <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                No high-risk static JavaScript heuristics detected in extension code.
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Content Scripts & Workers */}
        {activeTab === 'content_scripts' && (
          <div className="space-y-6 text-xs">
            {/* Background Worker */}
            <div className="border border-slate-200 rounded-lg p-4 bg-slate-50/50">
              <h4 className="font-bold text-slate-800 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-indigo-600" />
                Background Worker &amp; Service Scripts
              </h4>
              <div className="space-y-1.5 text-slate-700">
                <p>
                  <span className="font-semibold text-slate-900">Service Worker: </span>
                  <span className="font-mono">{background.service_worker || 'None (V2 or Non-Worker)'}</span>
                </p>
                <p>
                  <span className="font-semibold text-slate-900">Persistent Execution: </span>
                  <span>{background.is_persistent ? 'Yes (Runs continuously in background)' : 'No (Event-driven / Ephemeral)'}</span>
                </p>
                {background.scripts && background.scripts.length > 0 && (
                  <div>
                    <span className="font-semibold text-slate-900">Background Scripts: </span>
                    <span className="font-mono">{background.scripts.join(', ')}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Content Scripts */}
            <div>
              <h4 className="font-bold text-slate-800 uppercase tracking-wider mb-2">
                Injected Content Scripts ({content_scripts.length})
              </h4>
              {content_scripts.length > 0 ? (
                <div className="space-y-3">
                  {content_scripts.map((cs, i) => (
                    <div key={i} className="border border-slate-200 rounded-lg p-3 bg-white space-y-1.5">
                      <div className="flex justify-between items-center">
                        <span className="font-semibold text-slate-800">
                          Injection Rule #{i + 1}
                        </span>
                        <span className="text-[11px] bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono">
                          run_at: {cs.run_at}
                        </span>
                      </div>
                      <div className="text-slate-600">
                        <span className="font-medium text-slate-700">Matches: </span>
                        <span className="font-mono text-indigo-700">{cs.matches.join(', ')}</span>
                      </div>
                      <div className="text-slate-600">
                        <span className="font-medium text-slate-700">Files: </span>
                        <span className="font-mono text-slate-800">{cs.js.join(', ')}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 italic">No content scripts declared in manifest.</p>
              )}
            </div>
          </div>
        )}

        {/* Tab 4: Content Security Policy */}
        {activeTab === 'csp' && (
          <div className="space-y-4 text-xs">
            <div className="border border-slate-200 rounded-lg p-4 bg-slate-50/50 space-y-3">
              <h4 className="font-bold text-slate-800 uppercase tracking-wider">
                Raw Content Security Policy
              </h4>
              <pre className="p-3 bg-white border border-slate-200 rounded font-mono text-[11px] text-slate-800 whitespace-pre-wrap break-all">
                {csp.raw || "No custom CSP declared (default secure Chrome sandbox applies)"}
              </pre>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                <div className={`p-3 rounded-lg border ${csp.allows_unsafe_eval ? 'bg-red-50 border-red-200 text-red-900' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}`}>
                  <span className="font-bold block mb-1">unsafe-eval</span>
                  <span>{csp.allows_unsafe_eval ? 'Permitted (Insecure: eval execution allowed)' : 'Blocked (Secure)'}</span>
                </div>

                <div className={`p-3 rounded-lg border ${csp.allows_unsafe_inline ? 'bg-amber-50 border-amber-200 text-amber-900' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}`}>
                  <span className="font-bold block mb-1">unsafe-inline</span>
                  <span>{csp.allows_unsafe_inline ? 'Permitted (Weak inline script protection)' : 'Blocked (Secure)'}</span>
                </div>

                <div className={`p-3 rounded-lg border ${csp.allows_remote_scripts ? 'bg-red-50 border-red-200 text-red-900' : 'bg-emerald-50 border-emerald-200 text-emerald-900'}`}>
                  <span className="font-bold block mb-1">Remote Origins</span>
                  <span>{csp.allows_remote_scripts ? 'Permitted (External script loading)' : 'Blocked (Self-contained)'}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
