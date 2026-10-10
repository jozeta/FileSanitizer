import React, { useState } from 'react';
import { DomainIntelligence } from '../types';
import {
  Globe,
  ShieldAlert,
  Calendar,
  Server,
  AlertTriangle,
  CheckCircle2,
  Info,
  Copy,
  Check,
  Eye,
  Network
} from 'lucide-react';

interface DomainAnalyticsCardProps {
  domainInfo: DomainIntelligence;
  thumbnailUrl?: string;
}

export const DomainAnalyticsCard: React.FC<DomainAnalyticsCardProps> = ({ domainInfo, thumbnailUrl }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showLowConfidence, setShowLowConfidence] = useState(false);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const puny = domainInfo.punycode_analysis;
  const whois = domainInfo.whois || {};
  const dns = domainInfo.dns_records || {};
  const net = (domainInfo.network || {}) as Record<string, any>;
  const obf = domainInfo.obfuscation_analysis;
  const coHosted = domainInfo.co_hosted_domains || [];
  const ownerIntel = (domainInfo.owner_intelligence || {}) as Record<string, any>;
  const relatedDomains = domainInfo.related_domains || [];
  const pivots = domainInfo.ownership_pivots;
  const strongRelated = relatedDomains.filter(r => r.confidence !== 'low');
  const lowRelated = relatedDomains.filter(r => r.confidence === 'low');
  const visibleRelated = showLowConfidence ? relatedDomains : strongRelated;
  const confStyle: Record<string, string> = {
    high: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    medium: 'bg-amber-50 text-amber-700 border-amber-200',
    low: 'bg-slate-100 text-slate-600 border-slate-200',
  };
  const pivotStyle: Record<string, string> = {
    ok: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    skipped: 'bg-slate-100 text-slate-500 border-slate-200',
    blocked: 'bg-red-50 text-red-700 border-red-200',
    failed: 'bg-amber-50 text-amber-700 border-amber-200',
    timeout: 'bg-amber-50 text-amber-700 border-amber-200',
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden mb-6">
      {/* Header */}
      <div className="px-6 py-4 bg-gradient-to-r from-blue-50/80 via-slate-50 to-white border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-100/70 text-blue-700 rounded-lg">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-800 flex items-center gap-2">
              Domain &amp; Infrastructure Intelligence
              {domainInfo.is_ip ? (
                <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-purple-100 text-purple-800 border border-purple-200">
                  IP Address
                </span>
              ) : (
                <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-blue-100 text-blue-800 border border-blue-200">
                  Domain Name
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-500 font-mono mt-0.5">
              Target: <span className="font-semibold text-slate-700">{domainInfo.target}</span>
            </p>
          </div>
        </div>

        {/* Quick Badges */}
        <div className="flex items-center gap-2">
          {puny?.is_homograph && (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-red-100 text-red-800 border border-red-200 animate-pulse">
              <ShieldAlert className="w-3.5 h-3.5 mr-1" />
              Homograph Impersonation
            </span>
          )}
          {typeof whois.domain_age_days === 'number' && !isNaN(whois.domain_age_days) && (
            <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${
              whois.domain_age_days < 30
                ? 'bg-amber-100 text-amber-800 border-amber-300'
                : 'bg-emerald-100 text-emerald-800 border-emerald-200'
            }`}>
              <Calendar className="w-3.5 h-3.5 mr-1" />
              {whois.domain_age_formatted || `${whois.domain_age_days} Days Old`}
            </span>
          )}
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Live Browser Capture / Screenshot */}
        {thumbnailUrl && (
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row items-center gap-4">
            <div className="w-full sm:w-48 h-32 rounded-lg overflow-hidden border border-slate-300 shadow-xs shrink-0 bg-white">
              <img
                src={thumbnailUrl}
                alt={`Live preview for ${domainInfo.target}`}
                className="w-full h-full object-cover"
              />
            </div>
            <div className="flex-1 text-left space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                  Live Sandboxed Browser Capture
                </span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Rendered visual snapshot of <span className="font-mono font-bold text-slate-800">{domainInfo.target}</span> captured inside an isolated headless sandbox.
              </p>
              <a
                href={thumbnailUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center text-xs font-semibold text-blue-600 hover:text-blue-800 underline mt-1"
              >
                Open Full-Resolution Preview &rarr;
              </a>
            </div>
          </div>
        )}

        {/* 1. Punycode & Homograph Impersonation Warning Banner */}
        {puny?.is_homograph && (
          <div className="bg-red-50 border-2 border-red-300 rounded-xl p-4 shadow-xs">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-6 h-6 text-red-600 shrink-0 mt-0.5" />
              <div className="space-y-2 flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-red-900 uppercase tracking-wide">
                    Punycode Homograph Impersonation Attack Detected
                  </h4>
                  <span className="text-xs font-mono font-semibold bg-red-200/80 text-red-900 px-2 py-0.5 rounded">
                    CRITICAL PHISHING RISK
                  </span>
                </div>
                <p className="text-xs text-red-800 leading-relaxed">
                  This domain uses internationalized Punycode to masquerade as a well-known brand or legitimate host.
                  To a human user, the address appears identical or visually confusable with the legitimate target.
                </p>

                {/* Visual Comparison Box */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                  <div className="bg-white border border-red-200 rounded-lg p-3">
                    <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                      Raw ASCII / Punycode (Network Level):
                    </span>
                    <div className="font-mono text-sm font-bold text-slate-800 break-all bg-slate-50 p-2 rounded border border-slate-200">
                      {domainInfo.target}
                    </div>
                  </div>

                  <div className="bg-white border border-red-200 rounded-lg p-3">
                    <span className="text-[11px] font-semibold text-red-700 uppercase tracking-wider flex items-center gap-1 mb-1">
                      <Eye className="w-3.5 h-3.5" />
                      Visual User Appearance (Address Bar Lookalike):
                    </span>
                    <div className="font-mono text-sm font-bold text-red-700 break-all bg-red-100/60 p-2 rounded border border-red-300">
                      {puny.unicode_rendered || puny.visual_appearance}
                    </div>
                    {puny.simulated_latin && (
                      <div className="text-[11px] text-slate-600 mt-2 block font-medium">
                        Target Brand Masqueraded (ASCII Latin):{' '}
                        <span className="font-mono font-bold text-emerald-800 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-300">
                          {puny.simulated_latin}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Lookalike target & confusable characters breakdown */}
                {((puny.spoofed_chars && puny.spoofed_chars.length > 0) || (puny.homograph_confusables && puny.homograph_confusables.length > 0)) && (
                  <div className="mt-3 pt-3 border-t border-red-200/60">
                    <span className="text-xs font-semibold text-red-900 block mb-1.5">
                      Confusable Cyrillic / Non-ASCII Characters Used in Spoof:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {(puny.spoofed_chars || []).map((c, i) => (
                        <div key={i} className="inline-flex items-center gap-1.5 bg-white border border-red-200 px-2 py-1 rounded text-xs">
                          <span className="font-bold text-red-700 font-mono text-sm">{c.char}</span>
                          <span className="text-slate-400">&rarr;</span>
                          <span className="text-slate-600 font-mono">Latin '{c.latin_lookalike}'</span>
                          <span className="text-[10px] text-slate-400">({c.codepoint} {c.name})</span>
                        </div>
                      ))}
                      {(puny.homograph_confusables || []).map((c, i) => (
                        <div key={`h-${i}`} className="inline-flex items-center gap-1.5 bg-white border border-red-200 px-2 py-1 rounded text-xs">
                          <span className="font-bold text-red-700 font-mono text-sm">{c.char}</span>
                          <span className="text-slate-400">&rarr;</span>
                          <span className="text-slate-600 font-mono">Latin '{c.lookalike_latin}'</span>
                          <span className="text-[10px] text-slate-400">({c.script} {c.code_point})</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* 2. Obfuscation Techniques Banner */}
        {obf?.is_obfuscated && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
              <div className="space-y-1.5 flex-1">
                <h4 className="text-xs font-bold text-amber-900 uppercase tracking-wide">
                  Address Obfuscation Detected
                </h4>
                <p className="text-xs text-amber-800">
                  The submitted address format uses encoding tricks to evade automated URL scanners and filters.
                </p>
                <div className="space-y-1 pt-1">
                  {obf.techniques.map((t, idx) => (
                    <div key={idx} className="text-xs font-medium text-amber-900 flex items-baseline gap-2">
                      <span className="font-semibold text-amber-950">• {t.name}:</span>
                      <span className="text-amber-800">{t.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 3. Grid: Registration / WHOIS & Network Infrastructure */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* WHOIS & Registration */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 mb-3">
              <Calendar className="w-4 h-4 text-blue-600" />
              WHOIS &amp; RDAP Registration Intelligence
            </h4>

            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Registrar:</span>
                <span className="font-semibold text-slate-800 text-right">{whois.registrar || 'Not Disclosed / Unknown'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Registration Date:</span>
                <span className="font-mono text-slate-800">{whois.registration_date || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Expiration Date:</span>
                <span className="font-mono text-slate-800">{whois.expiration_date || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Domain Age:</span>
                <span className={`font-semibold ${typeof whois.domain_age_days === 'number' && !isNaN(whois.domain_age_days) && whois.domain_age_days < 30 ? 'text-amber-700 font-bold' : 'text-slate-800'}`}>
                  {typeof whois.domain_age_days === 'number' && !isNaN(whois.domain_age_days)
                    ? (whois.domain_age_formatted || `${whois.domain_age_days} Days`)
                    : 'N/A / Unrecorded'}
                  {typeof whois.domain_age_days === 'number' && !isNaN(whois.domain_age_days) && whois.domain_age_days < 30 && ' (Newly Registered)'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Registrant Org:</span>
                <span className="font-semibold text-slate-800">{whois.registrant_org || 'Privacy Protected / Redacted'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">DNSSEC:</span>
                <span className="font-medium text-slate-700 flex items-center gap-1">
                  {whois.dnssec ? (
                    <><CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Signed</>
                  ) : (
                    <><Info className="w-3.5 h-3.5 text-slate-400" /> Unsigned</>
                  )}
                </span>
              </div>
              {whois.nameservers && whois.nameservers.length > 0 && (
                <div className="pt-1">
                  <span className="text-slate-500 font-medium block mb-1">Authoritative Nameservers:</span>
                  <div className="flex flex-wrap gap-1">
                    {whois.nameservers.map((ns, idx) => (
                      <span key={idx} className="bg-white px-2 py-0.5 rounded text-[11px] font-mono text-slate-600 border border-slate-200">
                        {ns}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Network & Host Infrastructure */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 mb-3">
              <Server className="w-4 h-4 text-purple-600" />
              Network &amp; Autonomous System (ASN)
            </h4>

            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Primary IP:</span>
                <span className="font-mono font-semibold text-slate-800 flex items-center gap-1">
                  {net.ip || dns.a?.[0] || 'Unresolved'}
                  {(net.ip || dns.a?.[0]) && (
                    <button
                      onClick={() => copyToClipboard(String(net.ip || dns.a?.[0] || ''), 'ip')}
                      className="text-slate-400 hover:text-slate-600"
                      title="Copy IP"
                    >
                      {copiedKey === 'ip' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Identified Owner / Org:</span>
                <span className="font-semibold text-slate-800 text-right">{ownerIntel.owner_name || net.org || whois.registrant_org || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Corporate Network:</span>
                <span className="font-mono text-slate-700 text-right">{ownerIntel.network_name || net.network_name || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Autonomous System:</span>
                <span className="font-semibold text-slate-800">{ownerIntel.asn || net.asn || 'N/A'} {((ownerIntel.asn_org || net.as_org) && (ownerIntel.asn_org || net.as_org) !== (ownerIntel.asn || net.asn)) && `(${ownerIntel.asn_org || net.as_org})`}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">ISP / Carrier:</span>
                <span className="font-medium text-slate-700">{ownerIntel.isp || net.isp || 'N/A'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-200">
                <span className="text-slate-500 font-medium">Location:</span>
                <span className="font-medium text-slate-700">{net.city ? `${net.city}, ` : ''}{net.country || 'N/A'}</span>
              </div>

              {/* Allocated IP Ranges & CIDRs */}
              {(ownerIntel.ip_range || (ownerIntel.cidrs && ownerIntel.cidrs.length > 0)) && (
                <div className="py-2 border-b border-slate-200">
                  <span className="text-slate-500 font-medium block mb-1">
                    Allocated IP Ranges &amp; CIDRs:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {ownerIntel.ip_range && (
                      <span className="bg-purple-50 text-purple-700 px-2 py-0.5 rounded text-[11px] font-mono border border-purple-200">
                        {ownerIntel.ip_range}
                      </span>
                    )}
                    {ownerIntel.cidrs?.map((c: string, idx: number) => (
                      <span key={idx} className="bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded text-[11px] font-mono border border-indigo-200">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Other Domains Owned / Associated Hosts */}
              {ownerIntel.more_domains && ownerIntel.more_domains.length > 0 && (
                <div className="py-2 border-b border-slate-200">
                  <span className="text-slate-500 font-medium block mb-1">
                    Other Domains / Hosts Owned by Same Entity ({ownerIntel.more_domains.length}):
                  </span>
                  <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pr-1">
                    {ownerIntel.more_domains.map((d: string, idx: number) => (
                      <span key={idx} className="bg-slate-100 hover:bg-blue-50 px-2 py-0.5 rounded text-[11px] font-mono text-slate-700 border border-slate-200 hover:border-blue-300">
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Co-hosted domains on this IP */}
              <div className="pt-2">
                <span className="text-slate-500 font-medium block mb-1">
                  Co-hosted Domains on Same IP ({coHosted.length}):
                </span>
                {coHosted.length > 0 ? (
                  <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pr-1">
                    {coHosted.map((d, idx) => (
                      <span key={idx} className="bg-white px-2 py-0.5 rounded text-[11px] font-mono text-slate-700 border border-slate-200 hover:border-blue-300">
                        {d}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-[11px] text-slate-400 italic">No public co-hosted domains discovered</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Ownership Pivots: other domains owned by the same entity */}
        {pivots?.performed && (
          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-100/70 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                <Network className="w-4 h-4 text-indigo-600" />
                Related Domains &amp; Ownership Pivots ({strongRelated.length}{lowRelated.length > 0 ? ` + ${lowRelated.length} weak` : ''})
              </h4>
              <span className="text-[11px] text-slate-500 font-mono">
                {pivots.asn || 'AS ?'}{pivots.asn_holder ? ` · ${pivots.asn_holder}` : ''}{pivots.elapsed_s !== undefined ? ` · ${pivots.elapsed_s}s` : ''}
              </span>
            </div>

            <div className="p-4 space-y-4 text-xs">
              <p className="text-slate-500">
                Domains likely controlled by the same owner, found by pivoting on the Autonomous System, the corporate network block,
                the IPs, certificates and DNS policy records of <span className="font-mono font-semibold text-slate-700">{domainInfo.target}</span>.
                All pivots are passive.
              </p>

              {pivots.is_shared_infrastructure && pivots.shared_reason && (
                <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 text-amber-800 rounded-lg px-3 py-2">
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                  <span>{pivots.shared_reason}</span>
                </div>
              )}

              {/* Pivot status chips */}
              {pivots.pivots && pivots.pivots.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {pivots.pivots.map((pv, idx) => (
                    <span
                      key={idx}
                      title={pv.detail || pv.status}
                      className={`px-2 py-0.5 rounded border text-[11px] font-medium ${pivotStyle[pv.status] || pivotStyle.skipped}`}
                    >
                      {pv.name}: {pv.status === 'ok' ? `${pv.found} found` : pv.status}
                    </span>
                  ))}
                </div>
              )}

              {/* Related domains table */}
              {visibleRelated.length > 0 ? (
                <div className="border border-slate-200 rounded-lg overflow-hidden">
                  <div className="max-h-96 overflow-y-auto">
                    <table className="w-full text-left">
                      <thead className="bg-slate-50 sticky top-0 text-[11px] uppercase tracking-wide text-slate-500">
                        <tr>
                          <th className="px-3 py-2 font-semibold">Domain</th>
                          <th className="px-3 py-2 font-semibold">Relationship</th>
                          <th className="px-3 py-2 font-semibold">Evidence</th>
                          <th className="px-3 py-2 font-semibold">Confidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {visibleRelated.map((r) => (
                          <tr key={r.domain} className="hover:bg-slate-50/70 align-top">
                            <td className="px-3 py-2 font-mono font-semibold text-slate-800 whitespace-nowrap">
                              {r.domain}
                              {r.ips.length > 0 && (
                                <div className="text-[10px] font-normal text-slate-400">{r.ips.slice(0, 2).join(', ')}</div>
                              )}
                            </td>
                            <td className="px-3 py-2">
                              <div className="flex flex-wrap gap-1">
                                {r.relationship_labels.map((l, i) => (
                                  <span key={i} className="px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 text-[10px]">{l}</span>
                                ))}
                              </div>
                            </td>
                            <td className="px-3 py-2 text-slate-600">
                              {r.evidence.slice(0, 2).map((e, i) => (
                                <div key={i} className="font-mono text-[10px] break-all">{e}</div>
                              ))}
                              {r.sources.length > 1 && (
                                <div className="text-[10px] text-emerald-600 mt-0.5">Corroborated by {r.sources.join(' + ')}</div>
                              )}
                            </td>
                            <td className="px-3 py-2">
                              <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${confStyle[r.confidence]}`}>
                                {r.confidence}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <span className="text-[11px] text-slate-400 italic">No related domains discovered through ownership pivots</span>
              )}

              {lowRelated.length > 0 && (
                <button
                  onClick={() => setShowLowConfidence(v => !v)}
                  className="text-[11px] font-medium text-indigo-600 hover:text-indigo-800"
                >
                  {showLowConfidence ? 'Hide' : 'Show'} {lowRelated.length} low-confidence association{lowRelated.length > 1 ? 's' : ''} (shared hosting, provider infrastructure, vanity DNS)
                </button>
              )}

              {/* Owned infrastructure */}
              {((pivots.asn_prefixes && pivots.asn_prefixes.length > 0) || (pivots.spf_ip_ranges && pivots.spf_ip_ranges.length > 0)) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {pivots.asn_prefixes && pivots.asn_prefixes.length > 0 && (
                    <div>
                      <span className="text-slate-500 font-medium block mb-1">
                        Prefixes announced by {pivots.asn} ({pivots.asn_prefix_count}):
                      </span>
                      <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pr-1">
                        {pivots.asn_prefixes.map((p, i) => (
                          <span key={i} className="bg-purple-50 text-purple-700 px-2 py-0.5 rounded text-[11px] font-mono border border-purple-200">{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {pivots.spf_ip_ranges && pivots.spf_ip_ranges.length > 0 && (
                    <div>
                      <span className="text-slate-500 font-medium block mb-1">
                        Mail-sending IP ranges authorised in SPF ({pivots.spf_ip_ranges.length}):
                      </span>
                      <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pr-1">
                        {pivots.spf_ip_ranges.map((p, i) => (
                          <span key={i} className="bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded text-[11px] font-mono border border-indigo-200">{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 4. Full DNS Resource Records */}
        <div className="border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 bg-slate-100/70 border-b border-slate-200">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Globe className="w-4 h-4 text-blue-600" />
              Active DNS Resource Records (A, AAAA, MX, NS, TXT, SOA)
            </h4>
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
            {/* A Records */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
              <span className="font-bold text-slate-600 block mb-1 text-[11px] uppercase tracking-wide">A (IPv4)</span>
              {dns.a && dns.a.length > 0 ? (
                <ul className="space-y-1 font-mono text-slate-800">
                  {dns.a.map((ip, i) => <li key={i} className="break-all">{ip}</li>)}
                </ul>
              ) : <span className="text-slate-400 italic">None</span>}
            </div>

            {/* AAAA Records */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
              <span className="font-bold text-slate-600 block mb-1 text-[11px] uppercase tracking-wide">AAAA (IPv6)</span>
              {dns.aaaa && dns.aaaa.length > 0 ? (
                <ul className="space-y-1 font-mono text-slate-800">
                  {dns.aaaa.map((ip, i) => <li key={i} className="break-all">{ip}</li>)}
                </ul>
              ) : <span className="text-slate-400 italic">None</span>}
            </div>

            {/* MX Records */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
              <span className="font-bold text-slate-600 block mb-1 text-[11px] uppercase tracking-wide">MX (Mail Exchange)</span>
              {dns.mx && dns.mx.length > 0 ? (
                <ul className="space-y-1 text-slate-800">
                  {dns.mx.map((m, i) => {
                    const host = typeof m === 'object' ? m.host : m;
                    const priority = typeof m === 'object' ? m.priority : null;
                    return (
                      <li key={i} className="font-mono flex items-center justify-between gap-1 break-all">
                        <span>{host}</span>
                        {priority !== null && (
                          <span className="text-[10px] bg-slate-200 text-slate-700 px-1 rounded font-sans">
                            p:{priority}
                          </span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              ) : <span className="text-slate-400 italic">None</span>}
            </div>

            {/* NS Records */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80">
              <span className="font-bold text-slate-600 block mb-1 text-[11px] uppercase tracking-wide">NS (Nameservers)</span>
              {dns.ns && dns.ns.length > 0 ? (
                <ul className="space-y-1 font-mono text-slate-800">
                  {dns.ns.map((ns, i) => <li key={i} className="break-all">{ns}</li>)}
                </ul>
              ) : <span className="text-slate-400 italic">None</span>}
            </div>

            {/* TXT Records */}
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80 md:col-span-2">
              <span className="font-bold text-slate-600 block mb-1 text-[11px] uppercase tracking-wide">TXT (SPF, DMARC, Domain Verifications)</span>
              {dns.txt && dns.txt.length > 0 ? (
                <ul className="space-y-1.5 font-mono text-[11px] text-slate-800 max-h-32 overflow-y-auto pr-1">
                  {dns.txt.map((t, i) => (
                    <li key={i} className="break-all bg-white p-1.5 rounded border border-slate-200">
                      {t}
                    </li>
                  ))}
                </ul>
              ) : <span className="text-slate-400 italic">None</span>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
