import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { ShieldCheck, AlertTriangle, Image as ImageIcon, Lock, Unlock, ArrowRight, ExternalLink, Link2, ZoomIn, X, Globe, ChevronDown, ChevronUp, Server } from 'lucide-react';
import { UrlItem, EnrichedIocItem } from '../types';
import { InvestigateAssetButton } from './InvestigateAssetButton';
import { NetworkIocEnrichmentPanel } from './NetworkIocEnrichmentPanel';

interface UrlExplorerProps {
  urls?: UrlItem[];
  onSelectJob?: (newJobId: string) => void;
  jobId?: string;
  initialEnriched?: Record<string, EnrichedIocItem>;
}

const LOOKALIKE_MAP: Record<string, string> = {
  // Cyrillic lowercase
  'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'п': 'n',
  'т': 't', 'в': 'b', 'г': 'r', 'к': 'k', 'м': 'm', 'н': 'h',
  // Cyrillic uppercase
  'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
  'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
  // Greek
  'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'κ': 'k',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
  'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
};

function decodePunycodeLabel(input: string): string {
  if (!input.toLowerCase().startsWith('xn--')) return input;
  const puny = input.slice(4).toLowerCase();
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = '-';

  let n = initialN;
  let i = 0;
  let bias = initialBias;
  const output: number[] = [];

  const delimPos = puny.lastIndexOf(delimiter);
  let pos = 0;
  if (delimPos >= 0) {
    for (let j = 0; j < delimPos; j++) {
      output.push(puny.charCodeAt(j));
    }
    pos = delimPos + 1;
  }

  while (pos < puny.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= puny.length) break;
      const charCode = puny.charCodeAt(pos++);
      let digit: number;
      if (charCode - 48 < 10) digit = charCode - 22;
      else if (charCode - 65 < 26) digit = charCode - 65;
      else if (charCode - 97 < 26) digit = charCode - 97;
      else digit = base;

      i += digit * w;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (digit < t) break;
      w *= (base - t);
    }

    const outLen = output.length + 1;
    let delta = Math.floor((i - oldi) / (oldi === 0 ? damp : 2));
    delta += Math.floor(delta / outLen);
    let k = 0;
    while (delta > Math.floor(((base - tmin) * tmax) / 2)) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    bias = k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));

    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

export function decodePunycodeDomain(domain: string): string {
  if (!domain || !domain.toLowerCase().includes('xn--')) return domain;
  return domain
    .split('.')
    .map(label => label.toLowerCase().startsWith('xn--') ? decodePunycodeLabel(label) : label)
    .join('.');
}

const getVisualAppearance = (item: UrlItem): string => {
  const puny = (item as any).domain_intelligence?.punycode_analysis;
  if (puny?.unicode_rendered && !puny.unicode_rendered.toLowerCase().includes('xn--')) {
    return puny.unicode_rendered;
  }
  if (puny?.visual_appearance && !puny.visual_appearance.toLowerCase().includes('xn--')) {
    return puny.visual_appearance;
  }
  const ind = item.indicators?.find(i => i.includes('visually renders as') || i.includes('visually masquerades as'));
  if (ind) {
    const match = ind.match(/visually (?:renders|masquerades) as '([^']+)'/);
    if (match && !match[1].toLowerCase().includes('xn--')) {
      return match[1];
    }
  }
  if (puny?.simulated_latin && !puny.simulated_latin.toLowerCase().includes('xn--')) {
    return puny.simulated_latin;
  }
  if (item.domain && item.domain.toLowerCase().includes('xn--')) {
    const decoded = decodePunycodeDomain(item.domain);
    if (decoded && !decoded.toLowerCase().includes('xn--')) {
      return decoded;
    }
  }
  return item.domain || '';
};

const getTargetBrand = (item: UrlItem): string | null => {
  const puny = (item as any).domain_intelligence?.punycode_analysis;
  if (puny?.simulated_latin && puny.simulated_latin !== item.domain) {
    return puny.simulated_latin;
  }
  const ind = item.indicators?.find(i => i.includes('masquerading as'));
  if (ind) {
    const m = ind.match(/masquerading as '([^']+)'/);
    if (m && m[1] !== item.domain) return m[1];
  }
  if (item.domain && item.domain.toLowerCase().includes('xn--')) {
    const decoded = decodePunycodeDomain(item.domain);
    const latin = Array.from(decoded).map(ch => LOOKALIKE_MAP[ch] || ch).join('');
    if (latin !== item.domain && latin !== decoded) return latin;
  }
  return null;
};

export const UrlExplorer: React.FC<UrlExplorerProps> = ({
  urls = [],
  onSelectJob,
  jobId,
  initialEnriched
}) => {
  const [lightboxScreenshot, setLightboxScreenshot] = useState<{ url: string; domain: string } | null>(null);
  const [expandedSubdomains, setExpandedSubdomains] = useState<Record<number, boolean>>({});

  const toggleSubdomains = (index: number) => {
    setExpandedSubdomains(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  // Close lightbox modal on ESC key & lock body scroll
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && lightboxScreenshot) {
        setLightboxScreenshot(null);
      }
    };
    if (lightboxScreenshot) {
      window.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [lightboxScreenshot]);

  if (urls.length === 0) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 text-center text-slate-500 shadow-sm">
        <p className="text-sm">No external URLs or hyperlinks discovered in this file.</p>
      </div>
    );
  }

  const formatCertEntity = (val?: string | Record<string, string>): string => {
    if (!val) return 'Unknown';
    if (typeof val === 'string') return val;
    return val.organizationName || val.commonName || Object.values(val)[0] || 'Unknown';
  };

  const renderReputationBadge = (
    status: string,
    details?: any,
    abuseDetails?: any,
    alienDetails?: any
  ) => {
    const norm = (status || 'UNKNOWN').toUpperCase();

    if (abuseDetails && abuseDetails.abuse_confidence_score !== undefined) {
      if (abuseDetails.abuse_confidence_score > 0) {
        return (
          <span className="text-rose-700 font-bold" title={`ISP: ${abuseDetails.isp || 'N/A'}, Reports: ${abuseDetails.total_reports}`}>
            {abuseDetails.abuse_confidence_score}% CONFIDENCE
          </span>
        );
      }
      return (
        <span className="text-emerald-700 font-semibold text-[11px]" title={`ISP: ${abuseDetails.isp || 'N/A'}`}>
          0% ABUSE (CLEAN)
        </span>
      );
    }

    if (alienDetails && alienDetails.pulse_count !== undefined) {
      if (alienDetails.pulse_count > 0) {
        return (
          <span className="text-rose-700 font-bold" title={`Tags: ${(alienDetails.tags || []).join(', ')}`}>
            {alienDetails.pulse_count} PULSES ({alienDetails.threat_score}/10)
          </span>
        );
      }
      return (
        <span className="text-emerald-700 font-semibold text-[11px]">
          0 PULSES (CLEAN)
        </span>
      );
    }

    if (norm === 'CLEAN' || norm === 'BENIGN') {
      return <span className="text-emerald-700 font-bold">CLEAN</span>;
    }
    if (norm === 'MALICIOUS') {
      return (
        <span className="text-rose-700 font-bold">
          MALICIOUS {details && details.total ? `(${details.malicious}/${details.total})` : ''}
        </span>
      );
    }
    if (norm === 'SUSPICIOUS') {
      return (
        <span className="text-amber-700 font-bold">
          SUSPICIOUS {details && details.total ? `(${details.suspicious}/${details.total})` : ''}
        </span>
      );
    }
    if (norm === 'NOT_FOUND') {
      return (
        <span className="text-emerald-700 font-semibold text-[11px]" title="Target not listed in threat feed database (Clean / Unseen)">
          CLEAN (UNSEEN)
        </span>
      );
    }
    if (norm === 'INTERNAL_TARGET') {
      return (
        <span className="text-purple-700 font-semibold text-[11px]" title="SSRF Protected: Private / Internal network destination">
          INTERNAL / PRIVATE
        </span>
      );
    }
    if (norm === 'RATE_LIMITED') {
      return (
        <span className="text-amber-600 font-semibold text-[11px]" title="API key rate limit reached (e.g. 4 req/min on VirusTotal free tier)">
          RATE LIMITED
        </span>
      );
    }
    if (norm === 'NOT_CONFIGURED') {
      return <span className="text-slate-400 font-medium text-[11px]">NOT CONFIGURED</span>;
    }
    if (norm === 'AUTH_ERROR') {
      return <span className="text-rose-600 font-semibold text-[11px]" title="API key unauthorized or forbidden">AUTH ERROR</span>;
    }
    if (norm === 'PENDING') {
      return <span className="text-blue-600 font-medium text-[11px] animate-pulse">CHECKING...</span>;
    }
    return <span className="text-slate-600 font-medium text-[11px]">{norm}</span>;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-bold text-slate-900 tracking-tight">
          Discovered URLs & Reputation Analysis ({urls.length})
        </h3>
        <span className="text-xs text-slate-500 font-mono">
          SSRF Guard Active
        </span>
      </div>

      {jobId && urls.length > 0 && (
        <NetworkIocEnrichmentPanel
          jobId={jobId}
          extractedIocs={urls.map((u) => u.domain || u.url).filter(Boolean)}
          initialEnriched={initialEnriched}
          onNavigateToJob={onSelectJob}
          title="Discovered Domains & Host Quick-Enrichment"
          subtitle="Enriches discovered domain destinations with autonomous systems, BGP prefixes, FCrDNS verification, and threat intelligence."
        />
      )}

      <div className="grid grid-cols-1 gap-4">
        {urls.map((item, idx) => {
          return (
            <div
              key={idx}
              className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm hover:border-slate-300 transition-all"
            >
              <div className="flex flex-col md:flex-row md:items-start justify-between gap-5">
                <div className="flex-1 min-w-0">
                  {/* Top line: Protocol, Domain, Shortener Badge, Risk Badge, HTTP status, TLS Valid */}
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className="px-2.5 py-0.5 bg-slate-100 text-slate-700 rounded-md text-xs font-mono font-medium">
                      {item.protocol.toUpperCase()}
                    </span>
                    <span className="font-bold text-sm text-slate-900 truncate">
                      {item.domain || 'Unknown Host'}
                    </span>

                    {/* URL Shortener Badge */}
                    {item.is_shortener && (
                      <span className="px-2.5 py-0.5 bg-amber-100 text-amber-900 border border-amber-200 rounded-md text-[11px] font-mono font-bold flex items-center gap-1">
                        <Link2 className="w-3 h-3 text-amber-700" />
                        URL Shortener (Masked Destination)
                      </span>
                    )}

                    <span className={`px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold uppercase ${
                      item.risk === 'MALICIOUS' ? 'bg-rose-100 text-rose-800' :
                      item.risk === 'HIGH RISK' ? 'bg-red-100 text-red-800' :
                      item.risk === 'MEDIUM RISK' ? 'bg-amber-100 text-amber-800' :
                      'bg-emerald-100 text-emerald-800'
                    }`}>
                      {item.risk}
                    </span>

                    {item.http_status && (
                      <span className={`px-2.5 py-0.5 rounded-md text-[11px] font-mono font-semibold ${
                        item.http_status >= 200 && item.http_status < 300 ? 'bg-emerald-100 text-emerald-800' :
                        item.http_status >= 300 && item.http_status < 400 ? 'bg-amber-100 text-amber-800' :
                        'bg-rose-100 text-rose-800'
                      }`}>
                        HTTP {item.http_status}
                      </span>
                    )}

                    {item.tls_valid && (
                      <span className="text-[11px] text-emerald-600 font-mono font-medium flex items-center gap-1">
                        <ShieldCheck className="w-3.5 h-3.5" /> TLS Valid
                      </span>
                    )}
                  </div>

                  {/* Punycode Homograph Impersonation Alert Banner */}
                  {(item.domain?.includes('xn--') || item.indicators?.some(i => i.toLowerCase().includes('punycode'))) && (
                    <div className="mb-3 p-3.5 bg-rose-50 border border-rose-200 rounded-2xl flex items-start gap-3 shadow-2xs">
                      <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                      <div className="text-xs space-y-1">
                        <div className="font-bold text-rose-900 flex items-center gap-2 flex-wrap">
                          <span>⚠️ Punycode / Homograph Impersonation Attack</span>
                          <span className="px-2 py-0.5 bg-rose-200 text-rose-900 rounded font-mono text-[10px] uppercase font-bold">
                            High Evasion Risk
                          </span>
                        </div>
                        <div className="text-rose-800 font-mono text-xs leading-relaxed space-y-1">
                          <div>
                            <span className="text-slate-500">Encoded ASCII Domain:</span>{' '}
                            <span className="font-bold text-slate-900 bg-white px-1.5 py-0.5 rounded border border-rose-200/80">
                              {item.domain}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500">Visual User Appearance:</span>{' '}
                            <span className="font-bold text-rose-700 bg-white px-2 py-0.5 rounded border border-rose-300 text-sm tracking-wide">
                              {getVisualAppearance(item)}
                            </span>
                          </div>
                          {(() => {
                            const target = getTargetBrand(item);
                            if (target && target !== item.domain) {
                              return (
                                <div>
                                  <span className="text-slate-500">Target Spoofed Brand (Latin):</span>{' '}
                                  <span className="font-bold text-emerald-800 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-300">
                                    {target}
                                  </span>
                                </div>
                              );
                            }
                            return null;
                          })()}
                        </div>
                        <p className="text-[11px] text-rose-700">
                          Attackers use internationalized lookalike characters (homoglyphs) to visually impersonate trusted legitimate services while routing victims to hostile infrastructure.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Full URL & VirusTotal Search Button */}
                  <div className="text-xs text-slate-600 font-mono break-all mb-3 bg-slate-50 p-3 rounded-xl border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="truncate flex-1 font-medium">{item.url}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <InvestigateAssetButton
                        ioc={item.redirect_url || item.url}
                        onNavigateToJob={onSelectJob}
                        label="Investigate Asset"
                      />
                      <a
                        href={item.vt_web_link || `https://www.virustotal.com/gui/search/${encodeURIComponent(item.url)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-[11px] font-sans font-medium text-indigo-600 hover:text-indigo-800 shrink-0 bg-white px-2.5 py-1 rounded-lg border border-slate-200 hover:bg-slate-100 shadow-sm transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        <span>Lookup on VirusTotal</span>
                      </a>
                    </div>
                  </div>

                  {/* Redirect information & Deep Target Analysis */}
                  {item.redirect_url && (
                    <div className="mb-3 p-3 bg-amber-50/60 border border-amber-200 rounded-xl space-y-2">
                      <div className="text-xs text-amber-900 font-mono flex items-center gap-1.5 flex-wrap">
                        <ArrowRight className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                        <span className="font-semibold text-amber-800">Redirects to Real Destination:</span>
                        <span className="text-slate-900 font-bold truncate">{item.redirect_url}</span>
                      </div>

                      {item.target_analysis && (
                        <div className="bg-white border border-amber-200/80 rounded-lg p-2.5 text-[11px] font-mono space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-slate-500 font-bold">Destination Analysis:</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              item.target_analysis.risk === 'MALICIOUS' ? 'bg-rose-100 text-rose-800' :
                              item.target_analysis.risk === 'HIGH RISK' ? 'bg-red-100 text-red-800' :
                              item.target_analysis.risk === 'MEDIUM RISK' ? 'bg-amber-100 text-amber-800' :
                              'bg-emerald-100 text-emerald-800'
                            }`}>
                              Risk: {item.target_analysis.risk}
                            </span>
                            {item.target_analysis.http_status && (
                              <span className="text-slate-600">
                                HTTP {item.target_analysis.http_status}
                              </span>
                            )}
                            {item.target_analysis.tls_valid && (
                              <span className="text-emerald-700 font-semibold">TLS Secure</span>
                            )}
                          </div>
                          {item.target_analysis.indicators.length > 0 && (
                            <div className="text-amber-800 text-[10px]">
                              {item.target_analysis.indicators.join(' • ')}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Reputation and SSRF indicators */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-xs font-mono mb-3">
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">Heuristics</span>
                      <span className="font-semibold text-slate-800">{item.reputation.heuristic}</span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">VirusTotal</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.virus_total, item.reputation.virus_total_details)}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">URLhaus</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.urlhaus)}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">Safe Browsing</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.safe_browsing)}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">ThreatFox</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.threatfox || 'CLEAN')}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">urlscan.io</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.urlscan || 'NOT_CONFIGURED')}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">AbuseIPDB</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.abuseipdb || 'NOT_CONFIGURED', undefined, item.reputation.abuseipdb_details)}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">AlienVault OTX</span>
                      <span className="font-semibold text-slate-800">
                        {renderReputationBadge(item.reputation.alienvault_otx || 'NOT_CONFIGURED', undefined, undefined, item.reputation.alienvault_details)}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-50 border border-slate-100 rounded-xl">
                      <span className="text-slate-400 block text-[10px]">SSRF Safe</span>
                      <span className={`font-semibold ${item.is_ssrf_safe ? 'text-emerald-700' : 'text-rose-700'}`}>
                        {item.is_ssrf_safe ? 'YES (Public)' : 'NO (Blocked)'}
                      </span>
                    </div>
                  </div>

                  {/* TLS Certificate Analysis Breakdown */}
                  {item.certificate && (
                    <div className="mt-3 p-3.5 bg-slate-50 border border-slate-200 rounded-2xl text-xs font-mono space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1.5 font-bold text-slate-800">
                          {item.certificate.valid ? (
                            <Lock className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Unlock className="w-3.5 h-3.5 text-rose-600" />
                          )}
                          <span>HTTPS Certificate Analysis</span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          item.certificate.valid ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                        }`}>
                          {item.certificate.valid ? (item.certificate.tls_version || 'Valid TLS') : 'Untrusted / Incomplete'}
                        </span>
                      </div>

                      {item.certificate.valid ? (
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-1 text-[11px]">
                          <div>
                            <span className="text-slate-400 block text-[10px]">Issuer (CA)</span>
                            <span className="text-slate-700 font-medium truncate block" title={formatCertEntity(item.certificate.issuer)}>
                              {formatCertEntity(item.certificate.issuer)}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[10px]">Subject</span>
                            <span className="text-slate-700 font-medium truncate block" title={formatCertEntity(item.certificate.subject)}>
                              {formatCertEntity(item.certificate.subject)}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[10px]">Cipher Suite</span>
                            <span className="text-slate-700 font-medium truncate block" title={item.certificate.cipher || 'Standard'}>
                              {item.certificate.cipher || 'Standard'}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[10px]">Expiration</span>
                            <span className={`font-semibold block ${item.certificate.is_expired ? 'text-rose-600' : 'text-emerald-700'}`}>
                              {item.certificate.is_expired
                                ? 'Expired'
                                : item.certificate.days_remaining !== undefined && item.certificate.days_remaining !== null
                                  ? `${item.certificate.days_remaining} days left`
                                  : 'Valid'}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <div className="text-rose-700 text-xs flex items-center gap-1.5 pt-1">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                          <span>{item.certificate.error || 'SSL/TLS handshake or certificate verification failed.'}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Indicators / Warnings */}
                  {item.indicators.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      {item.indicators.map((ind, i) => (
                        <div key={i} className="text-xs text-amber-900 bg-amber-50/70 border border-amber-200/60 px-3 py-1.5 rounded-lg flex items-center gap-2">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                          <span>{ind}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Sandboxed Website Screenshot Preview with Lightbox Modal */}
                {item.screenshot_available && item.screenshot_url ? (
                  <div className="w-full md:w-56 shrink-0">
                    <div className="text-[11px] font-mono text-slate-500 mb-1 flex items-center justify-between">
                      <span className="flex items-center gap-1 font-semibold text-slate-700">
                        <ImageIcon className="w-3.5 h-3.5 text-indigo-600" />
                        <span>Website Preview</span>
                      </span>
                      <span className="text-[10px] text-indigo-600 font-semibold flex items-center gap-0.5">
                        <ZoomIn className="w-3 h-3" /> Enlarge
                      </span>
                    </div>
                    <div
                      onClick={() => setLightboxScreenshot({ url: item.screenshot_url!, domain: item.domain || item.url })}
                      className="border border-slate-200 hover:border-indigo-400 rounded-2xl overflow-hidden shadow-xs hover:shadow-md bg-slate-100 aspect-video relative group cursor-pointer transition-all"
                    >
                      <img
                        src={item.screenshot_url}
                        alt={`Screenshot of ${item.domain || item.url}`}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
                        loading="lazy"
                      />
                      <div className="absolute inset-0 bg-slate-900/0 group-hover:bg-slate-900/30 transition-colors flex items-center justify-center">
                        <span className="opacity-0 group-hover:opacity-100 bg-white/95 text-slate-900 px-3 py-1 rounded-full text-xs font-semibold shadow-md flex items-center gap-1.5 transition-opacity">
                          <ZoomIn className="w-3.5 h-3.5 text-indigo-600" /> Click to Enlarge
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="w-full md:w-56 shrink-0">
                    <div className="text-[11px] font-mono text-slate-400 mb-1 flex items-center gap-1">
                      <ImageIcon className="w-3.5 h-3.5 text-slate-400" />
                      <span>Website Preview</span>
                    </div>
                    <div className="border border-slate-200 rounded-2xl bg-slate-100/80 aspect-video flex flex-col items-center justify-center p-3 text-center shadow-xs">
                      <div className="w-8 h-8 rounded-full bg-slate-200/90 flex items-center justify-center mb-1.5 text-slate-400">
                        <ImageIcon className="w-4 h-4" />
                      </div>
                      <span className="text-[11px] text-slate-500 font-medium leading-tight">
                        No Screenshot Available
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Discovered Subdomains & Resolved IPs (Subfinder + dnsx) */}
              {(() => {
                const subfinderData = item.subfinder_dnsx;
                const subdomains: Array<{ subdomain: string; ips?: string[] }> = subfinderData?.subdomains?.map(s => ({
                  subdomain: s.subdomain,
                  ips: s.ips || []
                })) || (item.subdomains || []).map(s => ({ subdomain: s, ips: [] }));
                if (subdomains.length === 0) return null;

                const isExpanded = !!expandedSubdomains[idx];
                const totalIps = subfinderData?.discovered_ips?.length || Array.from(new Set(subdomains.flatMap(s => s.ips || []))).length;

                return (
                  <div className="mt-4 pt-4 border-t border-slate-100">
                    <button
                      type="button"
                      onClick={() => toggleSubdomains(idx)}
                      className="w-full flex items-center justify-between p-3 rounded-2xl bg-cyan-50/60 hover:bg-cyan-50 border border-cyan-200/80 transition-all text-left"
                    >
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <div className="p-1.5 bg-cyan-100 text-cyan-800 rounded-lg">
                          <Globe className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-bold text-slate-900 font-sans">
                              Discovered Subdomains &amp; Resolved IPs
                            </span>
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-200 text-cyan-900 uppercase">
                              Subfinder + dnsx
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-500 font-sans">
                            {subdomains.length} {subdomains.length === 1 ? 'subdomain' : 'subdomains'} • {totalIps} resolved {totalIps === 1 ? 'IPv4 address' : 'IPv4 addresses'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 text-xs text-cyan-800 font-medium px-2 py-1 rounded-lg bg-white/80 border border-cyan-200/60 shadow-2xs">
                        <span>{isExpanded ? 'Hide' : 'View Details'}</span>
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="mt-3 p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-3">
                        <div className="flex items-center justify-between text-[11px] text-slate-500 flex-wrap gap-2">
                          <span className="font-mono">
                            Command pipeline: <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 text-slate-800 font-bold">subfinder -silent -d {item.domain} | dnsx -silent -a -resp</code>
                          </span>
                          <span className="text-emerald-700 font-semibold flex items-center gap-1">
                            <Server className="w-3 h-3" /> Live DNS A-Records
                          </span>
                        </div>

                        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
                          <table className="min-w-full divide-y divide-slate-200 text-xs font-mono">
                            <thead className="bg-slate-50">
                              <tr>
                                <th className="px-3 py-2 text-left font-semibold text-slate-600">Subdomain</th>
                                <th className="px-3 py-2 text-left font-semibold text-slate-600">Resolved IPv4</th>
                                <th className="px-3 py-2 text-right font-semibold text-slate-600">Actions</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                              {subdomains.map((sub, sIdx) => (
                                <tr key={sIdx} className="hover:bg-slate-50/80 transition-colors">
                                  <td className="px-3 py-2 text-slate-900 font-semibold break-all">
                                    <div className="flex items-center gap-1.5">
                                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 shrink-0"></span>
                                      <span>{sub.subdomain}</span>
                                    </div>
                                  </td>
                                  <td className="px-3 py-2">
                                    {sub.ips && sub.ips.length > 0 ? (
                                      <div className="flex flex-wrap gap-1">
                                        {sub.ips.map((ip, ipIdx) => (
                                          <span
                                            key={ipIdx}
                                            className="px-1.5 py-0.5 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded text-[11px] font-mono"
                                          >
                                            {ip}
                                          </span>
                                        ))}
                                      </div>
                                    ) : (
                                      <span className="text-slate-400 italic text-[11px]">Unresolved</span>
                                    )}
                                  </td>
                                  <td className="px-3 py-2 text-right">
                                    <InvestigateAssetButton
                                      ioc={sub.subdomain}
                                      iocType="domain"
                                      onNavigateToJob={onSelectJob}
                                      label="Investigate"
                                      compact={true}
                                    />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          );
        })}
      </div>

      {/* Screenshot Lightbox Modal with Quick Fade Effect */}
      {lightboxScreenshot && typeof document !== 'undefined' && createPortal(
        <div
          onClick={(e) => {
            if (e.target === e.currentTarget) setLightboxScreenshot(null);
          }}
          className="fixed inset-0 bg-slate-900/75 backdrop-blur-sm z-[9999] flex items-center justify-center p-4 sm:p-6 animate-overlay-fade"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="bg-white border border-slate-200 rounded-3xl max-w-4xl w-full shadow-2xl animate-modal-fade flex flex-col max-h-[90vh] overflow-hidden my-auto"
          >
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-100 bg-white flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl border border-indigo-100">
                  <ImageIcon className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-900 text-sm">
                    Sandboxed Web Screenshot: {lightboxScreenshot.domain}
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    Captured safely in isolated headless Chromium browser sandbox
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setLightboxScreenshot(null)}
                className="p-1.5 rounded-xl text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                aria-label="Close Preview"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body / Image */}
            <div className="p-6 bg-slate-50 flex-1 overflow-y-auto flex items-center justify-center min-h-[300px]">
              <div className="border border-slate-200 rounded-2xl overflow-hidden shadow-xs bg-white max-h-[70vh] flex items-center justify-center">
                <img
                  src={lightboxScreenshot.url}
                  alt={`Screenshot of ${lightboxScreenshot.domain}`}
                  className="w-full h-auto object-contain max-h-[70vh]"
                />
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-3.5 bg-slate-50 border-t border-slate-100 flex items-center justify-between shrink-0 rounded-b-3xl">
              <span className="text-[11px] text-slate-500">
                Press <kbd className="px-1.5 py-0.5 bg-white border border-slate-200 rounded text-slate-600 font-mono text-[10px]">ESC</kbd> or click outside to dismiss
              </span>
              <button
                type="button"
                onClick={() => setLightboxScreenshot(null)}
                className="px-4 py-2 bg-slate-200 hover:bg-slate-300 text-slate-800 font-semibold rounded-xl text-xs transition-colors"
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};
