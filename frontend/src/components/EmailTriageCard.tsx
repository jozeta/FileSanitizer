import React, { useState, useMemo } from 'react';
import {
  Mail,
  ShieldAlert,
  EyeOff,
  Paperclip,
  AlertTriangle,
  Download,
  Play,
  CheckCircle2,
  Server,
  Globe,
  Copy,
  Check,
  FileText,
  ShieldCheck,
  Search,
  Network,
  FileCode,
  AlignLeft,
  ExternalLink,
  ArrowRight
} from 'lucide-react';
import { formatBytes } from '../utils/formatters';
import { EmailInfo } from '../types';
import { apiClient } from '../api/client';
import { findReferencedJob } from '../utils/crossFileReferences';
import { InvestigateAssetButton } from './InvestigateAssetButton';
import { NetworkIocEnrichmentPanel } from './NetworkIocEnrichmentPanel';

interface EmailTriageCardProps {
  jobId: string;
  emailInfo?: EmailInfo;
  findings?: Array<{ category: string; severity: string; title: string; description: string; details?: any }>;
  onSelectJob?: (newJobId: string) => void;
  workspaceJobs?: any[];
}

export const EmailTriageCard: React.FC<EmailTriageCardProps> = ({
  jobId,
  emailInfo,
  findings = [],
  onSelectJob,
  workspaceJobs = []
}) => {
  const [activeTab, setActiveTab] = useState<'preview' | 'plaintext' | 'phishing' | 'transit' | 'headers' | 'raw' | 'graph'>('preview');
  const [analyzingAttIndex, setAnalyzingAttIndex] = useState<number | null>(null);
  const [analyzedJobs, setAnalyzedJobs] = useState<Record<number, string>>({});
  const [copiedText, setCopiedText] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [headerSearch, setHeaderSearch] = useState('');
  const [rawSearch, setRawSearch] = useState('');
  const [wrapRawLines, setWrapRawLines] = useState(true);

  const emailFindings = findings.filter(
    (f) =>
      f.category === 'structure' ||
      f.category === 'active_content' ||
      f.category === 'metadata' ||
      f.category === 'reputation' ||
      f.title.toLowerCase().includes('email') ||
      f.title.toLowerCase().includes('phishing') ||
      f.title.toLowerCase().includes('spoofing') ||
      f.title.toLowerCase().includes('spf') ||
      f.title.toLowerCase().includes('dkim') ||
      f.title.toLowerCase().includes('dmarc') ||
      f.title.toLowerCase().includes('tracking')
  );

  const emailIocs = useMemo(() => {
    const list: string[] = [];
    (emailInfo?.sender_ips || []).forEach(ip => list.push(ip));
    if (emailInfo?.from) {
      const m = emailInfo.from.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (m) list.push(m[1]);
    }
    (emailInfo?.transit_hops || []).forEach(h => {
      if (h.ip) list.push(h.ip);
    });
    return Array.from(new Set(list));
  }, [emailInfo]);

  const handleCopyPlaintext = () => {
    if (emailInfo?.body_plain) {
      navigator.clipboard.writeText(emailInfo.body_plain);
      setCopiedText(true);
      setTimeout(() => setCopiedText(false), 2000);
    }
  };

  const handleAnalyzeAttachment = async (index: number) => {
    try {
      setAnalyzingAttIndex(index);
      const res = await apiClient.analyzeEmailAttachment(jobId, index);
      setAnalyzedJobs((prev) => ({ ...prev, [index]: res.job_id }));
      if (onSelectJob && res.job_id) {
        onSelectJob(res.job_id);
      }
    } catch (e: any) {
      alert(`Failed to queue attachment: ${e.message}`);
    } finally {
      setAnalyzingAttIndex(null);
    }
  };

  const filteredHeaders = emailInfo?.headers
    ? Object.entries(emailInfo.headers).filter(
        ([k, v]) =>
          !headerSearch ||
          k.toLowerCase().includes(headerSearch.toLowerCase()) ||
          v.toLowerCase().includes(headerSearch.toLowerCase())
      )
    : [];

  const rawEmailContent = useMemo(() => {
    if (!emailInfo) return '';
    if (emailInfo.raw_email && emailInfo.raw_email.trim().length > 0) {
      return emailInfo.raw_email;
    }
    const headerLines = emailInfo.raw_headers || (emailInfo.all_headers && emailInfo.all_headers.length > 0
      ? emailInfo.all_headers.map(h => `${h.name}: ${h.value}`).join('\n')
      : Object.entries(emailInfo.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'));
    const body = emailInfo.body_plain || emailInfo.body_html_sanitized || '';
    return `${headerLines}\n\n${body}`;
  }, [emailInfo]);

  const rawLines = useMemo(() => {
    return rawEmailContent.split(/\r?\n/);
  }, [rawEmailContent]);

  const rawMatchCount = useMemo(() => {
    if (!rawSearch.trim()) return 0;
    const term = rawSearch.toLowerCase();
    return rawLines.filter(line => line.toLowerCase().includes(term)).length;
  }, [rawLines, rawSearch]);

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(rawEmailContent);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleDownloadRawEml = () => {
    if (!emailInfo) return;
    const blob = new Blob([rawEmailContent], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safeSubj = (emailInfo.subject || 'email').replace(/[^a-zA-Z0-9_\-]/g, '_');
    a.download = `${safeSubj}.eml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Neutralize any links in email preview: keep visual layout & styling intact, but point strictly to '#'
  const safePreviewHtml = useMemo(() => {
    if (!emailInfo) return '';
    const raw = emailInfo.body_html_sanitized || '<p class="text-slate-400 italic">No message body present</p>';
    if (!emailInfo.body_html_sanitized) return raw;

    // Replace any href="..." on <a> and <area> with href="#"
    return raw.replace(/<(a|area)\b([^>]*?)href=(["'])(.*?)\3([^>]*?)>/gi, (_match, tag, before, quote, href, after) => {
      const cleanHref = href.trim();
      const titleAttr = /title=/i.test(before + after) || cleanHref === '#' ? '' : ` title="Original Link: ${cleanHref.replace(/"/g, '&quot;')} (Neutered to '#' for safety)"`;
      const cleanedBefore = before.replace(/\s*(?:target|rel)=(["']).*?\1/gi, '');
      const cleanedAfter = after.replace(/\s*(?:target|rel)=(["']).*?\1/gi, '');
      return `<${tag}${cleanedBefore}href="#" data-original-href=${quote}${cleanHref}${quote}${titleAttr}${cleanedAfter}>`;
    });
  }, [emailInfo?.body_html_sanitized]);

  if (!emailInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Mail className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No email metadata available for this job.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-100 mb-5 gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-2xl border border-indigo-100 text-lg">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">Email & Message Security Dossier</h3>
              <p className="text-xs text-slate-500">
                Disassembled headers, safe visual render, MTA server transit hops, authentication & attachments.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {emailInfo.authentication && (
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold border flex items-center gap-1.5 ${
                  emailInfo.authentication.overall_trust === 'TRUSTED'
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : emailInfo.authentication.overall_trust === 'UNTRUSTED / SPOOFED'
                    ? 'bg-rose-50 text-rose-800 border-rose-200 animate-pulse'
                    : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                {emailInfo.authentication.overall_trust}
              </span>
            )}
            {emailInfo.tracking_pixel_count && emailInfo.tracking_pixel_count > 0 && (
              <span className="px-3 py-1 bg-amber-50 text-amber-800 border border-amber-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <EyeOff className="w-3.5 h-3.5 text-amber-600" />
                {emailInfo.tracking_pixel_count} Tracking Beacons
              </span>
            )}
            {emailInfo.attachment_count > 0 && (
              <span className="px-3 py-1 bg-slate-100 text-slate-700 border border-slate-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <Paperclip className="w-3.5 h-3.5 text-slate-600" />
                {emailInfo.attachment_count} Attachments
              </span>
            )}
          </div>
        </div>

        {/* Envelope Metadata Summary */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs mb-3">
          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Subject
            </span>
            <span className="text-slate-900 font-bold break-words">
              {emailInfo.subject || '(No Subject)'}
            </span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              From (Sender Header)
            </span>
            <span className="text-slate-900 font-medium break-all">
              {emailInfo.from || emailInfo.headers['from'] || '(Unknown Sender)'}
            </span>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              To (Recipients)
            </span>
            <div className="space-y-0.5">
              {emailInfo.recipients_details && emailInfo.recipients_details.length > 0 ? (
                emailInfo.recipients_details.map((r, rIdx) => (
                  <span key={rIdx} className="text-slate-900 font-medium break-all block">
                    {r.name ? `${r.name} ` : ''}{r.email ? `<${r.email}>` : ''} {r.addrtype ? `(${r.addrtype})` : ''}
                  </span>
                ))
              ) : (
                <span className="text-slate-800 font-medium break-all block">
                  {emailInfo.to || emailInfo.headers['to'] || 'Not specified'}
                </span>
              )}
            </div>
          </div>

          <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-semibold mb-1">
              Origination Date &amp; Client
            </span>
            <div className="text-slate-700 font-mono">
              <div>{emailInfo.date || emailInfo.headers['date'] || 'Not specified'}</div>
              {emailInfo.headers['x-mailer'] && (
                <div className="text-[10px] text-indigo-700 font-sans mt-0.5 font-semibold">
                  Mailer: {emailInfo.headers['x-mailer']}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-200 gap-1 overflow-x-auto pt-2">
          <button
            onClick={() => setActiveTab('preview')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'preview'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Visual Email Preview</span>
          </button>

          <button
            onClick={() => setActiveTab('plaintext')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'plaintext'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Extracted Plaintext Body</span>
          </button>

          <button
            onClick={() => setActiveTab('phishing')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'phishing'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Phishing & Spoofing Analysis</span>
            {emailFindings.length > 0 && (
              <span className="px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded-full text-[10px] font-bold">
                {emailFindings.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('transit')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'transit'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>MTA Server Transit Hops ({emailInfo.transit_hops?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('headers')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'headers'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>RFC 822 Headers ({Object.keys(emailInfo.headers).length})</span>
          </button>

          <button
            onClick={() => setActiveTab('raw')}
            className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
              activeTab === 'raw'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Raw Email & Headers</span>
          </button>

          {((emailInfo.attachment_graph && emailInfo.attachment_graph.length > 0) || (emailInfo.attachments && emailInfo.attachments.length > 0)) && (
            <button
              onClick={() => setActiveTab('graph')}
              className={`px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-2 cursor-pointer ${
                activeTab === 'graph'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Relationship Graph ({emailInfo.attachment_graph?.length || emailInfo.attachments.length})</span>
            </button>
          )}
        </div>

        {/* Tab 1: Visual Email Preview */}
        {activeTab === 'preview' && (
          <div className="pt-4">
            <div className="flex items-center justify-between text-xs text-slate-500 mb-2">
              <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                Sanitized Sandboxed Email HTML Preview (Scripts Stripped & Links Neutered to #)
              </span>
              <span>{emailInfo.has_html ? 'Rendered from HTML' : 'Plaintext Formatted'}</span>
            </div>
            <div
              className="border border-slate-200 rounded-2xl bg-white shadow-inner max-h-[600px] overflow-y-auto p-4"
              onClick={(e) => {
                const target = e.target as HTMLElement;
                const link = target.closest('a, area');
                if (link) {
                  // Prevent navigation or page scrolling on neutered links
                  e.preventDefault();
                }
              }}
              dangerouslySetInnerHTML={{
                __html: safePreviewHtml
              }}
            />
          </div>
        )}

        {/* Tab 2: Extracted Plaintext Body */}
        {activeTab === 'plaintext' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-700">
                Extracted Clean Message Text ({emailInfo.body_plain?.length || 0} characters)
              </span>
              <button
                onClick={handleCopyPlaintext}
                className="px-3 py-1.5 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedText ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedText ? 'Copied to Clipboard' : 'Copy Text'}</span>
              </button>
            </div>
            <div className="p-4 bg-slate-50 text-slate-800 rounded-2xl border border-slate-200 text-xs font-mono whitespace-pre-wrap max-h-[500px] overflow-y-auto leading-relaxed shadow-xs">
              {emailInfo.body_plain || '(Empty Message Body)'}
            </div>
          </div>
        )}

        {/* Tab 3: Phishing, Spoofing & Authentication */}
        {activeTab === 'phishing' && (
          <div className="pt-4 space-y-5">
            {/* Authentication Matrix */}
            {emailInfo.authentication && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div
                  className={`p-3.5 rounded-2xl border ${
                    emailInfo.authentication.spf.status === 'PASS'
                      ? 'bg-emerald-50/70 border-emerald-200'
                      : emailInfo.authentication.spf.status === 'FAIL' || emailInfo.authentication.spf.status === 'SOFTFAIL'
                      ? 'bg-rose-50/70 border-rose-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-600">SPF Auth</span>
                    <span
                      className={`text-xs font-extrabold px-2 py-0.5 rounded-full ${
                        emailInfo.authentication.spf.status === 'PASS'
                          ? 'bg-emerald-100 text-emerald-800'
                          : emailInfo.authentication.spf.status === 'FAIL'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {emailInfo.authentication.spf.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 truncate" title={emailInfo.authentication.spf.raw}>
                    {emailInfo.authentication.spf.raw || 'No Received-SPF header'}
                  </p>
                </div>

                <div
                  className={`p-3.5 rounded-2xl border ${
                    emailInfo.authentication.dkim.status === 'PASS'
                      ? 'bg-emerald-50/70 border-emerald-200'
                      : emailInfo.authentication.dkim.status === 'FAIL'
                      ? 'bg-rose-50/70 border-rose-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-600">DKIM Signature</span>
                    <span
                      className={`text-xs font-extrabold px-2 py-0.5 rounded-full ${
                        emailInfo.authentication.dkim.status === 'PASS'
                          ? 'bg-emerald-100 text-emerald-800'
                          : emailInfo.authentication.dkim.status === 'FAIL'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {emailInfo.authentication.dkim.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 truncate">
                    Domain: {emailInfo.authentication.dkim.domain || '(None)'}
                  </p>
                </div>

                <div
                  className={`p-3.5 rounded-2xl border ${
                    emailInfo.authentication.dmarc.status === 'PASS'
                      ? 'bg-emerald-50/70 border-emerald-200'
                      : emailInfo.authentication.dmarc.status === 'FAIL'
                      ? 'bg-rose-50/70 border-rose-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-600">DMARC Policy</span>
                    <span
                      className={`text-xs font-extrabold px-2 py-0.5 rounded-full ${
                        emailInfo.authentication.dmarc.status === 'PASS'
                          ? 'bg-emerald-100 text-emerald-800'
                          : emailInfo.authentication.dmarc.status === 'FAIL'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {emailInfo.authentication.dmarc.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 truncate">
                    Policy: {emailInfo.authentication.dmarc.policy || 'none'}
                  </p>
                </div>

                <div
                  className={`p-3.5 rounded-2xl border ${
                    emailInfo.authentication.alignment?.dmarc_aligned
                      ? 'bg-emerald-50/70 border-emerald-200'
                      : emailInfo.authentication.alignment
                      ? 'bg-rose-50/70 border-rose-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-600">DMARC Alignment</span>
                    <span
                      className={`text-xs font-extrabold px-2 py-0.5 rounded-full ${
                        emailInfo.authentication.alignment?.dmarc_aligned
                          ? 'bg-emerald-100 text-emerald-800'
                          : emailInfo.authentication.alignment
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {emailInfo.authentication.alignment?.dmarc_aligned ? 'ALIGNED' : (emailInfo.authentication.alignment ? 'BROKEN' : 'N/A')}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 truncate">
                    SPF: {emailInfo.authentication.alignment?.spf_aligned ? '✓' : '✗'} · DKIM: {emailInfo.authentication.alignment?.dkim_aligned ? '✓' : '✗'}
                  </p>
                </div>
              </div>
            )}

            {/* Deceptive Links Warning Table */}
            {emailInfo.deceptive_links && emailInfo.deceptive_links.length > 0 && (
              <div className="p-4 bg-rose-50/80 border border-rose-200 rounded-2xl">
                <div className="flex items-center gap-2 mb-2 text-rose-900 font-bold text-xs">
                  <AlertTriangle className="w-4 h-4 text-rose-600" />
                  <span>Deceptive Phishing Links Detected ({emailInfo.deceptive_links.length})</span>
                </div>
                <p className="text-[11px] text-rose-800 mb-3">
                  These links display a legitimate trusted domain in the visual email text, but navigate to an
                  entirely different malicious web server!
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono border-collapse">
                    <thead>
                      <tr className="border-b border-rose-200 text-rose-900 bg-rose-100/50">
                        <th className="py-2 px-3 text-left">Displayed Text</th>
                        <th className="py-2 px-3 text-left">Actual Destination Host</th>
                        <th className="py-2 px-3 text-left">Full Target URL</th>
                        <th className="py-2 px-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-rose-200/60">
                      {emailInfo.deceptive_links.map((dl, idx) => (
                        <tr key={idx} className="hover:bg-rose-100/30">
                          <td className="py-2 px-3 text-emerald-800 font-bold">{dl.displayed_text}</td>
                          <td className="py-2 px-3 text-rose-900 font-bold">{dl.destination_host}</td>
                          <td className="py-2 px-3 text-slate-600 break-all max-w-xs">{dl.actual_destination}</td>
                          <td className="py-2 px-3 text-right">
                            <InvestigateAssetButton
                              ioc={dl.actual_destination || dl.destination_host}
                              onNavigateToJob={onSelectJob}
                              compact
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Sender Domain Analysis Details */}
            {emailInfo.sender_analysis && (
              <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 text-xs space-y-2">
                <h4 className="font-bold text-slate-800 uppercase tracking-wider text-[11px]">
                  Sender Identity Inspection
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div>
                    <span className="text-slate-400 block text-[10px]">From Domain</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className="font-semibold text-slate-800">{emailInfo.sender_analysis.from_domain || 'N/A'}</span>
                      {emailInfo.sender_analysis.from_domain && (
                        <InvestigateAssetButton
                          ioc={emailInfo.sender_analysis.from_domain}
                          onNavigateToJob={onSelectJob}
                          compact
                        />
                      )}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Reply-To Domain</span>
                    <span
                      className={`font-semibold ${
                        emailInfo.sender_analysis.is_mismatched_reply_to ? 'text-rose-600 font-bold' : 'text-slate-800'
                      }`}
                    >
                      {emailInfo.sender_analysis.reply_to_domain || '(Matching)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Return-Path Domain</span>
                    <span className="font-semibold text-slate-800">
                      {emailInfo.sender_analysis.return_path_domain || 'N/A'}
                    </span>
                  </div>
                </div>
                {emailInfo.sender_analysis.impersonated_brand && (
                  <div className="p-2.5 bg-amber-50 border border-amber-200 rounded-xl text-amber-900 font-medium">
                    ⚠️ Potential Brand Impersonation: Sender claims identity "{emailInfo.sender_analysis.impersonated_brand}"
                    using generic webmail.
                  </div>
                )}
                {emailInfo.sender_analysis.is_vip_impersonation && (
                  <div className="p-2.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-900 font-semibold flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>
                      Executive / VIP Impersonation: Sender claims high-ranking title "{emailInfo.sender_analysis.vip_title || 'Executive'}" from an unaligned address.
                    </span>
                  </div>
                )}
                {(emailInfo.sender_analysis.has_homoglyphs || emailInfo.sender_analysis.is_punycode) && (
                  <div className="p-2.5 bg-amber-50 border border-amber-200 rounded-xl text-amber-900 font-medium space-y-1">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                      <span className="font-semibold">Deceptive Domain Homoglyph / Punycode Detected</span>
                    </div>
                    {emailInfo.sender_analysis.homoglyphs_details && emailInfo.sender_analysis.homoglyphs_details.length > 0 && (
                      <p className="text-[11px] font-mono text-amber-800 pl-6">
                        {emailInfo.sender_analysis.homoglyphs_details.join(' | ')}
                      </p>
                    )}
                  </div>
                )}
                {emailInfo.thread_hijacking?.suspected_hijacking && (
                  <div className="p-2.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-900 font-semibold flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                    <span>
                      Suspected Thread Hijacking: Subject simulates existing reply chain ('Re:') without authentic In-Reply-To / References headers.
                    </span>
                  </div>
                )}

                {emailInfo.sender_analysis.sender_domain_intelligence && (
                  <div className="mt-3 p-4 bg-white rounded-2xl border border-indigo-100 shadow-2xs space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-indigo-600" />
                        <h5 className="font-bold text-slate-900 text-xs">
                          Sender Domain Deep Intelligence: {emailInfo.sender_analysis.sender_domain_intelligence.target}
                        </h5>
                      </div>
                      {typeof emailInfo.sender_analysis.sender_domain_intelligence.whois?.domain_age_days === 'number' && !isNaN(emailInfo.sender_analysis.sender_domain_intelligence.whois.domain_age_days) && (
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          emailInfo.sender_analysis.sender_domain_intelligence.whois.domain_age_days < 30
                            ? 'bg-rose-100 text-rose-800 border border-rose-200'
                            : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                        }`}>
                          {emailInfo.sender_analysis.sender_domain_intelligence.whois.domain_age_formatted || `${emailInfo.sender_analysis.sender_domain_intelligence.whois.domain_age_days} Days Old`}
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 text-xs">
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/80">
                        <span className="text-[10px] text-slate-400 block uppercase font-semibold">Registrar</span>
                        <span className="font-semibold text-slate-800 truncate block">
                          {emailInfo.sender_analysis.sender_domain_intelligence.whois?.registrar || 'Unknown / Hidden'}
                        </span>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/80">
                        <span className="text-[10px] text-slate-400 block uppercase font-semibold">Registered Date</span>
                        <span className="font-mono text-slate-700 truncate block">
                          {emailInfo.sender_analysis.sender_domain_intelligence.whois?.registration_date || emailInfo.sender_analysis.sender_domain_intelligence.whois?.creation_date || 'N/A'}
                        </span>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/80">
                        <span className="text-[10px] text-slate-400 block uppercase font-semibold">Primary IP</span>
                        <span className="font-mono text-slate-800 font-bold truncate block">
                          {emailInfo.sender_analysis.sender_domain_intelligence.dns_records?.a?.[0] || emailInfo.sender_analysis.sender_domain_intelligence.dns_records?.A?.[0] || 'Unresolved'}
                        </span>
                      </div>
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/80">
                        <span className="text-[10px] text-slate-400 block uppercase font-semibold">Mail Servers (MX)</span>
                        <span className="font-mono text-slate-700 truncate block">
                          {emailInfo.sender_analysis.sender_domain_intelligence.dns_records?.MX?.join(', ') || 'No MX Records'}
                        </span>
                      </div>
                    </div>

                    {emailInfo.sender_analysis.sender_domain_intelligence.reverse_ip?.co_hosted_domains?.length > 0 && (
                      <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/80 text-[11px] font-mono">
                        <span className="text-slate-500 font-semibold block mb-1">
                          Co-Hosted Domains on Same IP ({emailInfo.sender_analysis.sender_domain_intelligence.reverse_ip.co_hosted_domains.length}):
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {emailInfo.sender_analysis.sender_domain_intelligence.reverse_ip.co_hosted_domains.slice(0, 8).map((d: string, idx: number) => (
                            <span key={idx} className="px-2 py-0.5 bg-white border border-slate-200 rounded text-slate-700">
                              {d}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Findings List */}
            {emailFindings.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
                  Security Warnings & Policy Triggers
                </h4>
                {emailFindings.map((f, i) => (
                  <div
                    key={i}
                    className={`p-3.5 rounded-2xl border flex items-start gap-3 ${
                      f.severity === 'critical'
                        ? 'bg-rose-50 border-rose-200 text-rose-900'
                        : f.severity === 'high'
                        ? 'bg-red-50 border-red-200 text-red-900'
                        : f.severity === 'medium'
                        ? 'bg-amber-50 border-amber-200 text-amber-900'
                        : 'bg-blue-50 border-blue-200 text-blue-900'
                    }`}
                  >
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                      <div className="font-bold text-xs">{f.title}</div>
                      <p className="text-xs opacity-90 mt-0.5 leading-relaxed">{f.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Server Transit Hops */}
        {activeTab === 'transit' && (
          <div className="pt-4 space-y-4">
            {jobId && emailIocs.length > 0 && (
              <NetworkIocEnrichmentPanel
                jobId={jobId}
                extractedIocs={emailIocs}
                onNavigateToJob={onSelectJob}
                title="Email Origin & MTA Relay Intelligence"
                subtitle="Enriches originating IP addresses, sender domains, and transit MTA relay servers with ASN, FCrDNS validation, and reputation."
              />
            )}
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>
                Chronological Mail Transfer Agent (MTA) Relay Pipeline (Origin Hop 1 ➔ Final Delivery Hop N)
              </span>
              <span className="font-mono">{emailInfo.transit_hops?.length || 0} Relay Hops</span>
            </div>

            {(!emailInfo.transit_hops || emailInfo.transit_hops.length === 0) ? (
              <p className="text-slate-400 text-xs italic p-4 text-center">No MTA Received headers found.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600">
                      <th className="py-2.5 px-3 text-left">Hop</th>
                      <th className="py-2.5 px-3 text-left">From Host / Relay</th>
                      <th className="py-2.5 px-3 text-left">IP Address</th>
                      <th className="py-2.5 px-3 text-left">Geo / Location</th>
                      <th className="py-2.5 px-3 text-left">ASN / Network</th>
                      <th className="py-2.5 px-3 text-left">Protocol</th>
                      <th className="py-2.5 px-3 text-left">Delay</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {emailInfo.transit_hops.map((hop) => (
                      <tr key={hop.hop_number} className="hover:bg-slate-50/60">
                        <td className="py-2.5 px-3 font-bold text-slate-700">#{hop.hop_number}</td>
                        <td className="py-2.5 px-3 text-slate-900 font-semibold max-w-xs break-all">
                          {hop.from_host}
                        </td>
                        <td className="py-2.5 px-3 text-indigo-600 font-semibold">{hop.ip || '—'}</td>
                        <td className="py-2.5 px-3 text-slate-700">
                          {hop.country} {hop.city ? `(${hop.city})` : ''}
                        </td>
                        <td className="py-2.5 px-3 text-slate-600 max-w-xs truncate" title={hop.asn}>
                          {hop.asn}
                        </td>
                        <td className="py-2.5 px-3 text-slate-500">{hop.protocol}</td>
                        <td className="py-2.5 px-3 font-semibold text-slate-600">
                          {hop.delay_seconds !== null && hop.delay_seconds !== undefined
                            ? `${hop.delay_seconds}s`
                            : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Raw RFC 822 Headers */}
        {activeTab === 'headers' && (
          <div className="pt-4 space-y-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={headerSearch}
                onChange={(e) => setHeaderSearch(e.target.value)}
                placeholder="Filter headers by key or value..."
                className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div className="p-4 bg-slate-50 text-slate-800 rounded-2xl border border-slate-200 text-xs font-mono max-h-96 overflow-y-auto space-y-1.5 shadow-inner">
              {filteredHeaders.map(([key, val]) => (
                <div key={key} className="break-all">
                  <span className="text-indigo-600 font-bold uppercase">{key}:</span>{' '}
                  <span className="text-slate-800">{val}</span>
                </div>
              ))}
              {filteredHeaders.length === 0 && (
                <p className="text-slate-400 italic">No headers match your filter.</p>
              )}
            </div>
          </div>
        )}

        {/* Tab: Raw RFC 822 Email Message & Headers */}
        {activeTab === 'raw' && (
          <div className="pt-4 space-y-3">
            {/* Top Toolbar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-50 p-3 rounded-2xl border border-slate-200">
              {/* Search in raw email */}
              <div className="relative flex-1 max-w-md">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={rawSearch}
                  onChange={(e) => setRawSearch(e.target.value)}
                  placeholder="Search raw email headers or body..."
                  className="w-full pl-9 pr-4 py-1.5 text-xs bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 font-sans"
                />
                {rawSearch && (
                  <span className="absolute right-3 top-2 text-[10px] font-mono text-slate-400">
                    {rawMatchCount} match{rawMatchCount !== 1 ? 'es' : ''}
                  </span>
                )}
              </div>

              {/* Action Buttons & Badges */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[11px] font-mono font-medium text-slate-500 bg-white px-2 py-1 rounded-lg border border-slate-200">
                  {rawLines.length} Lines • {formatBytes(new Blob([rawEmailContent]).size)}
                </span>

                <button
                  type="button"
                  onClick={() => setWrapRawLines(!wrapRawLines)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-xl border transition-colors flex items-center gap-1.5 cursor-pointer ${
                    wrapRawLines
                      ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
                      : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
                  }`}
                  title={wrapRawLines ? 'Word wrap enabled' : 'Horizontal scroll enabled'}
                >
                  <AlignLeft className="w-3.5 h-3.5" />
                  <span>{wrapRawLines ? 'Wrapped' : 'No Wrap'}</span>
                </button>

                <button
                  type="button"
                  onClick={handleCopyRaw}
                  className="px-3 py-1.5 text-xs font-semibold bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-xl transition-colors flex items-center gap-1.5 shadow-2xs cursor-pointer"
                  title="Copy full raw email content to clipboard"
                >
                  {copiedRaw ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                      <span className="text-emerald-700 font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-500" />
                      <span>Copy Raw</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleDownloadRawEml}
                  className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-colors flex items-center gap-1.5 shadow-xs cursor-pointer"
                  title="Download unmodified .eml file"
                >
                  <Download className="w-3.5 h-3.5 text-white" />
                  <span>Download .EML</span>
                </button>
              </div>
            </div>

            {/* Raw Code View with Line Numbers */}
            <div className="bg-slate-50 text-slate-800 rounded-2xl border border-slate-200 shadow-xs overflow-hidden flex flex-col max-h-[620px]">
              <div className="px-4 py-2 bg-slate-100 border-b border-slate-200 text-[11px] font-mono text-slate-500 flex items-center justify-between select-none">
                <span>RFC 822 / RFC 5322 Raw Stream Content</span>
                <span>UTF-8 / Plain Text</span>
              </div>
              <div className="overflow-auto flex-1 font-mono text-xs leading-relaxed p-4 bg-white">
                <table className="w-full border-collapse">
                  <tbody>
                    {rawLines.map((line, idx) => {
                      const lineNum = idx + 1;
                      const isMatch = rawSearch.trim() && line.toLowerCase().includes(rawSearch.toLowerCase());
                      const isHeaderLine = idx < 80 && /^[A-Za-z0-9-]+:/.test(line);

                      return (
                        <tr
                          key={idx}
                          className={`hover:bg-slate-50 transition-colors ${
                            isMatch ? 'bg-amber-100' : ''
                          }`}
                        >
                          <td className="align-top text-right pr-4 pl-1 py-0.5 text-slate-400 select-none text-[11px] font-mono w-12 border-r border-slate-200 shrink-0">
                            {lineNum}
                          </td>
                          <td className={`pl-4 py-0.5 font-mono text-xs text-slate-800 ${wrapRawLines ? 'break-all whitespace-pre-wrap' : 'whitespace-pre'}`}>
                            {isMatch ? (
                              <span>
                                {(() => {
                                  const parts = line.split(new RegExp(`(${rawSearch.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')})`, 'gi'));
                                  return parts.map((part, i) =>
                                    part.toLowerCase() === rawSearch.toLowerCase() ? (
                                      <mark key={i} className="bg-amber-300 text-slate-900 px-0.5 rounded font-bold">
                                        {part}
                                      </mark>
                                    ) : (
                                      <span key={i}>{part}</span>
                                    )
                                  );
                                })()}
                              </span>
                            ) : isHeaderLine ? (
                              <span>
                                {(() => {
                                  const colonIdx = line.indexOf(':');
                                  const hdrName = line.slice(0, colonIdx + 1);
                                  const hdrVal = line.slice(colonIdx + 1);
                                  return (
                                    <>
                                      <span className="text-cyan-700 font-bold">{hdrName}</span>
                                      <span className="text-slate-800">{hdrVal}</span>
                                    </>
                                  );
                                })()}
                              </span>
                            ) : line.startsWith('--') ? (
                              <span className="text-purple-700 font-bold">{line}</span>
                            ) : (
                              <span>{line || '\u00A0'}</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: Attachment & Structure Relationship Graph */}
        {activeTab === 'graph' && (
          <div className="pt-4 space-y-4">
            <div className="p-4 bg-indigo-50/70 border border-indigo-200 rounded-2xl flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold text-indigo-900 uppercase tracking-wider mb-0.5 flex items-center gap-1.5">
                  <Network className="w-4 h-4 text-indigo-600" />
                  Attachment & Payload Structure Relationship Graph
                </h4>
                <p className="text-xs text-indigo-800">
                  Visual topology mapping the origin message container, delivery payload streams, and nested payloads.
                </p>
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 bg-white border border-indigo-200 text-indigo-700 rounded-lg">
                {(emailInfo.attachment_graph?.length || emailInfo.attachments?.length || 0)} Entities
              </span>
            </div>

            {/* Tree View / Graph Cards */}
            <div className="p-5 bg-slate-50 rounded-2xl text-slate-800 font-mono text-xs space-y-4 border border-slate-200">
              {/* Root Node: Email Message */}
              <div className="p-3 bg-white rounded-xl border border-slate-200 flex items-center justify-between shadow-xs">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-indigo-600 rounded-lg text-white">
                    <Mail className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="font-bold text-slate-900">{emailInfo.subject || '(No Subject)'}</span>
                    <span className="text-[11px] text-slate-500 block font-sans">
                      RFC 822 Email Container • From: {emailInfo.from}
                    </span>
                  </div>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 font-bold">
                  ROOT MESSAGE
                </span>
              </div>

              {/* Connecting Edges and Attachment Nodes */}
              <div className="pl-6 border-l-2 border-dashed border-indigo-300 space-y-3 ml-4">
                {emailInfo.attachment_graph && emailInfo.attachment_graph.length > 0 ? (
                  emailInfo.attachment_graph.map((edge, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-xl border border-slate-200 hover:border-indigo-300 transition-colors shadow-xs">
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="text-indigo-600 font-bold flex items-center gap-2">
                          <span>↳</span>
                          <span>{edge.target}</span>
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                          {edge.relationship}
                        </span>
                      </div>
                      {edge.details && (
                        <p className="text-[11px] text-slate-500 font-sans pl-4">
                          {edge.details}
                        </p>
                      )}
                    </div>
                  ))
                ) : (
                  emailInfo.attachments.map((att, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-xl border border-slate-200 hover:border-indigo-300 transition-colors shadow-xs">
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="text-indigo-600 font-bold flex items-center gap-2">
                          <span>↳</span>
                          <span>{att.filename}</span>
                        </span>
                        <div className="flex items-center gap-1.5">
                          {att.is_dangerous && (
                            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-sans font-bold">
                              Dangerous
                            </span>
                          )}
                          {att.has_macros && (
                            <span className="text-[10px] px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 font-sans font-bold">
                              Macros
                            </span>
                          )}
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-mono border border-slate-200">
                            {formatBytes(att.size_bytes)}
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-slate-500 font-sans pl-4 flex items-center gap-3">
                        <span>MIME: {att.content_type}</span>
                        <span>SHA256: {att.sha256.slice(0, 16)}...</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Attachments Section with Download, Analyze, and Reputation Badges */}
      {emailInfo.attachments && emailInfo.attachments.length > 0 && (
        <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl border border-indigo-100">
                <Paperclip className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-bold text-slate-900">
                Extracted Email Attachments ({emailInfo.attachments.length})
              </h4>
            </div>
            <span className="text-[11px] text-slate-500">
              Download safely or submit directly for full deep analysis pipeline
            </span>
          </div>

          <div className="space-y-3">
            {emailInfo.attachments.map((att, i) => {
              const circlRep = att.reputation?.circl;
              const tfRep = att.reputation?.threatfox;
              const vtRep = att.reputation?.virustotal;
              const haRep = att.reputation?.hybrid_analysis;
              const matchedWorkspaceJob = findReferencedJob(att.filename, workspaceJobs, jobId) || (att.sha256 ? findReferencedJob(att.sha256, workspaceJobs, jobId) : null);
              const targetJobId = analyzedJobs[att.index] || matchedWorkspaceJob?.jobId;

              return (
                <div
                  key={i}
                  className={`p-4 rounded-2xl border transition-all ${
                    att.is_dangerous || (tfRep && tfRep.status === 'MALICIOUS') || (vtRep && vtRep.positives && vtRep.positives > 0) || (haRep && haRep.status === 'MALICIOUS')
                      ? 'bg-rose-50/50 border-rose-200'
                      : att.has_macros || (haRep && haRep.status === 'SUSPICIOUS')
                      ? 'bg-amber-50/50 border-amber-200'
                      : 'bg-slate-50/70 border-slate-200'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        {targetJobId && onSelectJob ? (
                          <button
                            onClick={() => onSelectJob(targetJobId)}
                            className="font-bold text-xs text-indigo-700 hover:text-indigo-900 hover:underline inline-flex items-center gap-1 cursor-pointer truncate max-w-[320px]"
                            title={`Navigate to analyzed workspace file: ${matchedWorkspaceJob?.filename || att.filename}`}
                          >
                            <span>{att.filename}</span>
                            <ExternalLink className="w-3 h-3 text-indigo-500 shrink-0" />
                          </button>
                        ) : (
                          <span className="font-bold text-xs text-slate-900 truncate" title={att.filename}>
                            {att.filename}
                          </span>
                        )}
                        {matchedWorkspaceJob && (
                          <span className="px-2 py-0.5 bg-indigo-100 text-indigo-800 rounded text-[10px] font-bold uppercase tracking-wider shrink-0 border border-indigo-200">
                            Workspace Artifact
                          </span>
                        )}
                        {att.is_dangerous && (
                          <span className="px-2 py-0.5 bg-rose-100 text-rose-800 rounded text-[10px] font-bold uppercase tracking-wider shrink-0">
                            Dangerous Executable
                          </span>
                        )}
                        {att.has_macros && (
                          <span className="px-2 py-0.5 bg-amber-100 text-amber-800 rounded text-[10px] font-bold uppercase tracking-wider shrink-0">
                            Office Macros
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] text-slate-500 font-mono space-x-2">
                        <span>{att.content_type}</span>
                        <span>•</span>
                        <span>{formatBytes(att.size_bytes)}</span>
                        {att.sha256 && (
                          <>
                            <span>•</span>
                            <span className="text-slate-400">SHA256: {att.sha256.slice(0, 16)}...</span>
                          </>
                        )}
                      </div>

                      {/* Nested Archive Members (e.g. .js / scripts inside .zip) */}
                      {att.inner_files && att.inner_files.length > 0 && (
                        <div className="mt-2.5 p-2.5 bg-slate-900/5 rounded-xl border border-slate-200/80 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600 block">
                            Extracted Archive Contents ({att.inner_files.length} payload member{att.inner_files.length > 1 ? 's' : ''}):
                          </span>
                          <div className="space-y-1">
                            {att.inner_files.map((inner, inIdx) => (
                              <div key={inIdx} className="flex items-center justify-between text-[11px] font-mono">
                                <span className={inner.is_dangerous ? "text-rose-700 font-bold flex items-center gap-1.5" : "text-slate-700 font-medium"}>
                                  {inner.is_dangerous && <span>⚠️</span>}
                                  {inner.filename}
                                </span>
                                <span className="text-slate-400">{formatBytes(inner.size)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Multi-API Reputation Badges */}
                      <div className="flex flex-wrap items-center gap-2 mt-2">
                        {/* CIRCL */}
                        {circlRep && (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                              circlRep.status === 'BENIGN_KNOWN'
                                ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                                : 'bg-slate-100 text-slate-600 border-slate-200'
                            }`}
                            title={circlRep.file_name ? `NSRL Known: ${circlRep.file_name}` : 'CIRCL Status'}
                          >
                            CIRCL: {circlRep.status === 'BENIGN_KNOWN' ? '✓ NSRL Known Benign' : 'Unseen'}
                          </span>
                        )}

                        {/* ThreatFox */}
                        {tfRep && (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                              tfRep.status === 'MALICIOUS'
                                ? 'bg-rose-100 text-rose-800 border-rose-300 font-bold'
                                : tfRep.status === 'CLEAN'
                                ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                                : 'bg-slate-100 text-slate-500 border-slate-200'
                            }`}
                          >
                            ThreatFox:{' '}
                            {tfRep.status === 'MALICIOUS'
                              ? `⚠️ ${tfRep.malware || 'Malware'}`
                              : tfRep.status === 'CLEAN'
                              ? 'Clean'
                              : 'Not Configured'}
                          </span>
                        )}

                        {/* VirusTotal */}
                        {vtRep && (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${
                              vtRep.positives && vtRep.positives > 0
                                ? 'bg-rose-100 text-rose-800 border-rose-300 font-bold'
                                : vtRep.status === 'CLEAN'
                                ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                                : 'bg-slate-100 text-slate-500 border-slate-200'
                            }`}
                          >
                            VirusTotal:{' '}
                            {vtRep.positives && vtRep.positives > 0
                              ? `⚠️ ${vtRep.positives}/${vtRep.total_engines || 0} Detections`
                              : vtRep.status === 'CLEAN'
                              ? '0 Detections'
                              : 'Not Configured'}
                          </span>
                        )}

                        {/* Hybrid Analysis (Falcon Sandbox) */}
                        {haRep && (
                          <a
                            href={haRep.report_url || (att.sha256 ? `https://hybrid-analysis.com/sample/${att.sha256}` : '#')}
                            target="_blank"
                            rel="noopener noreferrer"
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold border flex items-center gap-1 hover:underline ${
                              haRep.status === 'MALICIOUS'
                                ? 'bg-rose-100 text-rose-800 border-rose-300 font-bold'
                                : haRep.status === 'SUSPICIOUS'
                                ? 'bg-amber-100 text-amber-800 border-amber-300 font-bold'
                                : haRep.status === 'CLEAN'
                                ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                                : 'bg-slate-100 text-slate-500 border-slate-200'
                            }`}
                          >
                            <span>🦅 Hybrid Analysis:</span>
                            <span>
                              {haRep.threat_score !== undefined
                                ? `${haRep.threat_score}/100`
                                : haRep.status === 'NOT_CONFIGURED'
                                ? 'Not Configured'
                                : haRep.status || 'Unseen'}
                            </span>
                          </a>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 shrink-0">
                      <a
                        href={apiClient.getEmailAttachmentDownloadUrl(jobId, att.index)}
                        download={att.filename}
                        className="px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
                        title="Download attachment file directly"
                      >
                        <Download className="w-3.5 h-3.5 text-slate-500" />
                        <span>Download</span>
                      </a>

                      {targetJobId ? (
                        <button
                          onClick={() => onSelectJob && onSelectJob(targetJobId)}
                          className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
                          title={`Go to already analysed file '${matchedWorkspaceJob?.filename || att.filename}' in current workspace`}
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Go to already analysed file</span>
                          <ArrowRight className="w-3 h-3 ml-0.5" />
                        </button>
                      ) : (
                        <button
                          onClick={() => handleAnalyzeAttachment(att.index)}
                          disabled={analyzingAttIndex === att.index}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-400 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm cursor-pointer"
                          title="Submit this attachment to FileSanitizer for isolated deep scan"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>{analyzingAttIndex === att.index ? 'Queuing...' : 'Analyze File'}</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
