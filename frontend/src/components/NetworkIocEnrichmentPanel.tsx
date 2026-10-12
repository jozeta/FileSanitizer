import React, { useState } from 'react';
import {
  Zap,
  Globe,
  AlertTriangle,
  Loader2,
  Search,
  Check,
  Copy
} from 'lucide-react';
import { EnrichedIocItem } from '../types';
import { apiClient } from '../api/client';
import { InvestigateAssetButton } from './InvestigateAssetButton';

export interface NetworkIocEnrichmentPanelProps {
  jobId?: string;
  extractedIocs: string[];
  initialEnriched?: Record<string, EnrichedIocItem>;
  onNavigateToJob?: (jobId: string) => void;
  title?: string;
  subtitle?: string;
}

export const NetworkIocEnrichmentPanel: React.FC<NetworkIocEnrichmentPanelProps> = ({
  jobId,
  extractedIocs = [],
  initialEnriched = {},
  onNavigateToJob,
  title = 'Network IOC Quick-Enrichment',
  subtitle = 'Correlates extracted network indicators with Autonomous System Numbers (ASN), BGP network operators, FCrDNS verification, and threat intelligence verdicts.'
}) => {
  const [enrichedMap, setEnrichedMap] = useState<Record<string, EnrichedIocItem>>(initialEnriched);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<'all' | 'threats' | 'clean'>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Deduplicate and filter valid indicators
  const uniqueIocs = Array.from(
    new Set(
      extractedIocs
        .map((i) => (i || '').trim())
        .filter((i) => i.length > 2 && !i.includes('127.0.0.1') && !i.includes('localhost') && !i.includes('0.0.0.0'))
    )
  );

  const enrichedList = Object.values(enrichedMap);
  const hasEnrichedData = enrichedList.length > 0;

  const handleEnrich = async () => {
    if (!jobId || uniqueIocs.length === 0 || isLoading) return;
    setIsLoading(true);
    setErrorMessage(null);

    try {
      // Enrich up to 30 IOCs concurrently in a batch
      const targetBatch = uniqueIocs.slice(0, 30);
      const res = await apiClient.enrichJobIocs(jobId, targetBatch);

      if (res && res.enriched) {
        const nextMap: Record<string, EnrichedIocItem> = { ...enrichedMap };
        for (const item of res.enriched) {
          nextMap[item.indicator] = item;
        }
        setEnrichedMap(nextMap);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to enrich network IOCs.');
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredItems = enrichedList.filter((item) => {
    if (verdictFilter === 'threats') {
      const v = (item.verdict || '').toLowerCase();
      if (v !== 'malicious' && v !== 'suspicious') return false;
    } else if (verdictFilter === 'clean') {
      const v = (item.verdict || '').toLowerCase();
      if (v !== 'clean') return false;
    }

    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.indicator.toLowerCase().includes(q) ||
      (item.asn || '').toLowerCase().includes(q) ||
      (item.as_org || '').toLowerCase().includes(q) ||
      (item.country || '').toLowerCase().includes(q) ||
      (item.verdict || '').toLowerCase().includes(q)
    );
  });

  if (uniqueIocs.length === 0 && !hasEnrichedData) {
    return null;
  }

  return (
    <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-4">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-500" />
            <span>{title}</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">
              {uniqueIocs.length} Extracted
            </span>
          </h4>
          <p className="text-xs text-slate-600 mt-0.5">{subtitle}</p>
        </div>

        {jobId && (
          <button
            onClick={handleEnrich}
            disabled={isLoading || uniqueIocs.length === 0}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold inline-flex items-center gap-1.5 cursor-pointer shadow-2xs transition-colors shrink-0 ${
              isLoading
                ? 'bg-amber-100 text-amber-700 cursor-not-allowed'
                : 'bg-amber-600 hover:bg-amber-700 text-white'
            }`}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Enriching IOCs...</span>
              </>
            ) : hasEnrichedData ? (
              <>
                <Zap className="w-3.5 h-3.5" />
                <span>Re-Enrich Batch ({Math.min(uniqueIocs.length, 30)})</span>
              </>
            ) : (
              <>
                <Zap className="w-3.5 h-3.5" />
                <span>Quick-Enrich {Math.min(uniqueIocs.length, 30)} IOCs</span>
              </>
            )}
          </button>
        )}
      </div>

      {errorMessage && (
        <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-800 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {hasEnrichedData ? (
        <div className="space-y-3">
          {/* Quick Metrics & Filter */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
              <button
                onClick={() => setVerdictFilter('all')}
                className={`px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                  verdictFilter === 'all'
                    ? 'bg-slate-800 text-white'
                    : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                }`}
              >
                All ({enrichedList.length})
              </button>
              <button
                onClick={() => setVerdictFilter('threats')}
                className={`px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                  verdictFilter === 'threats'
                    ? 'bg-rose-600 text-white'
                    : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                }`}
              >
                Threats ({enrichedList.filter((i) => i.verdict === 'malicious' || i.verdict === 'suspicious').length})
              </button>
              <button
                onClick={() => setVerdictFilter('clean')}
                className={`px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                  verdictFilter === 'clean'
                    ? 'bg-emerald-600 text-white'
                    : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                }`}
              >
                Clean ({enrichedList.filter((i) => i.verdict === 'clean').length})
              </button>
            </div>

            <div className="relative min-w-[180px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter enriched IOCs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-hidden focus:border-amber-500"
              />
            </div>
          </div>

          {/* Enriched Items Table */}
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                <tr>
                  <th className="py-2.5 px-3 font-sans">Indicator</th>
                  <th className="py-2.5 px-3 font-sans">Type</th>
                  <th className="py-2.5 px-3 font-sans">Autonomous System &amp; Org</th>
                  <th className="py-2.5 px-3 font-sans">FCrDNS / PTR</th>
                  <th className="py-2.5 px-3 font-sans">Threat Verdict</th>
                  <th className="py-2.5 px-3 font-sans text-right">Pivot</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredItems.map((item, idx) => {
                  const fcrdnsValid = item.fcrdns?.is_fcrdns_valid;
                  const fcrdnsMismatch = item.fcrdns?.status === 'MISMATCH';

                  return (
                    <tr key={idx} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-2.5 px-3 font-bold text-slate-900">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate max-w-[180px]" title={item.indicator}>
                            {item.indicator}
                          </span>
                          <button
                            onClick={() => copyToClipboard(item.indicator, `ioc_${idx}`)}
                            className="text-slate-400 hover:text-slate-600 cursor-pointer"
                            title="Copy indicator"
                          >
                            {copiedKey === `ioc_${idx}` ? (
                              <Check className="w-3 h-3 text-emerald-600" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className="px-1.5 py-0.5 bg-slate-100 text-slate-700 rounded text-[10px] uppercase font-semibold">
                          {item.type}
                        </span>
                      </td>

                      <td className="py-2.5 px-3">
                        {item.asn || item.as_org ? (
                          <div className="text-slate-800">
                            <span className="font-bold text-blue-700">{item.asn || 'ASN'}</span>
                            <span className="text-slate-600 ml-1.5 truncate max-w-[200px]" title={item.as_org || ''}>
                              {item.as_org || ''}
                            </span>
                            {item.country && (
                              <span className="ml-1.5 px-1 py-0.2 rounded text-[10px] bg-slate-100 text-slate-600 font-sans">
                                {item.country}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400">-</span>
                        )}
                      </td>

                      <td className="py-2.5 px-3">
                        {item.fcrdns ? (
                          <div className="flex items-center gap-1.5">
                            {fcrdnsValid ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
                                FCrDNS Valid
                              </span>
                            ) : fcrdnsMismatch ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-800 border border-amber-300">
                                FCrDNS Diverged
                              </span>
                            ) : (
                              <span className="text-[10px] text-slate-500 font-sans">
                                {item.fcrdns.primary_ptr ? item.fcrdns.primary_ptr : 'No PTR'}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400">-</span>
                        )}
                      </td>

                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            item.verdict === 'malicious'
                              ? 'bg-rose-100 text-rose-800 border border-rose-300'
                              : item.verdict === 'suspicious'
                              ? 'bg-amber-100 text-amber-800 border border-amber-300'
                              : item.verdict === 'clean'
                              ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                              : 'bg-slate-100 text-slate-600'
                          }`}
                        >
                          {item.verdict}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 text-right">
                        <InvestigateAssetButton
                          ioc={item.indicator}
                          iocType={item.is_ip ? 'ip' : 'domain'}
                          compact={true}
                          onNavigateToJob={onNavigateToJob}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="p-3 bg-white rounded-xl border border-slate-200 text-xs text-slate-600 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-slate-400 shrink-0" />
            <span>
              <strong>{uniqueIocs.length} network indicators</strong> discovered in this file payload ready for automated BGP, ASN, and reputation enrichment.
            </span>
          </div>
          {jobId && (
            <button
              onClick={handleEnrich}
              disabled={isLoading}
              className="text-xs font-semibold text-amber-700 hover:text-amber-800 underline cursor-pointer shrink-0"
            >
              Run Batch Enrichment
            </button>
          )}
        </div>
      )}
    </div>
  );
};
