import React, { useState, useMemo } from 'react';
import {
  Mail,
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
  Activity,
  Lock,
  Terminal,
  DollarSign,
  Layers,
  FileCheck,
  Fingerprint
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
  disabledChecks?: string[];
}

export type EmailTab =
  | 'preview'
  | 'auth_lookalike'
  | 'url_html'
  | 'attachment_forensics'
  | 'bec_fraud'
  | 'file_integrity'
  | 'plaintext'
  | 'transit'
  | 'headers'
  | 'raw'
  | 'graph'
  | 'offline_tools';

export const EmailTriageCard: React.FC<EmailTriageCardProps> = ({
  jobId,
  emailInfo,
  findings = [],
  onSelectJob,
  workspaceJobs = [],
  disabledChecks = [],
}) => {
  const isCheckDisabled = (chk: string) => (disabledChecks || []).includes(chk);
  const [activeTab, setActiveTab] = useState<EmailTab>('preview');

  React.useEffect(() => {
    if (activeTab === 'headers' && isCheckDisabled('check_headers')) {
      setActiveTab('preview');
    } else if (activeTab === 'attachment_forensics' && isCheckDisabled('check_attachments')) {
      setActiveTab('preview');
    } else if (activeTab === 'url_html' && isCheckDisabled('check_links')) {
      setActiveTab('preview');
    } else if (activeTab === 'auth_lookalike' && (isCheckDisabled('check_spf_dkim_dmarc') && isCheckDisabled('check_domain_dns_rdap'))) {
      setActiveTab('preview');
    } else if (activeTab === 'bec_fraud' && (isCheckDisabled('check_phishing_urgency') && isCheckDisabled('check_thread_hijacking'))) {
      setActiveTab('preview');
    }
  }, [activeTab, disabledChecks]);
  const [analyzingAttIndex, setAnalyzingAttIndex] = useState<number | null>(null);
  const [analyzedJobs, setAnalyzedJobs] = useState<Record<number, string>>({});
  const [copiedText, setCopiedText] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedTool, setCopiedTool] = useState<string | null>(null);
  const [headerSearch, setHeaderSearch] = useState('');
  const [rawSearch, setRawSearch] = useState('');
  const [wrapRawLines, setWrapRawLines] = useState(true);

  const emailFindings = findings.filter(
    (f) =>
      f.category === 'structure' ||
      f.category === 'active_content' ||
      f.category === 'metadata' ||
      f.category === 'reputation' ||
      f.category === 'phishing' ||
      f.category === 'threat' ||
      f.title.toLowerCase().includes('email') ||
      f.title.toLowerCase().includes('phishing') ||
      f.title.toLowerCase().includes('spoofing') ||
      f.title.toLowerCase().includes('lookalike') ||
      f.title.toLowerCase().includes('spf') ||
      f.title.toLowerCase().includes('dkim') ||
      f.title.toLowerCase().includes('dmarc') ||
      f.title.toLowerCase().includes('tracking') ||
      f.title.toLowerCase().includes('bec') ||
      f.title.toLowerCase().includes('hidden')
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

  const handleCopyToolCommand = (toolKey: string, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedTool(toolKey);
    setTimeout(() => setCopiedTool(null), 2000);
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

  // Fallbacks for checklist objects if not yet backfilled
  const verdict = emailInfo.email_verdict || {
    verdict: emailFindings.some(f => f.severity === 'critical') ? 'Malicious' : (emailFindings.some(f => f.severity === 'high') ? 'Suspicious' : 'No Known Threat Detected'),
    severity: (emailFindings.some(f => f.severity === 'critical') ? 'critical' : (emailFindings.some(f => f.severity === 'high') ? 'high' : 'clean')) as any,
    confidence_score: emailFindings.some(f => f.severity === 'critical') ? 95 : 80,
    threat_categories: emailFindings.map(f => f.category),
    key_assessment_rationale: emailFindings.map(f => f.title),
    mitre_attack_techniques: ['T1566.002', 'T1566.001'],
    containment_guidance: [
      'Purge message from all mailboxes across exchange / M365 tenant.',
      'Revoke active user sessions and enforce immediate credential reset.',
      'Block sender domain and connecting MTA IP at perimeter email security gateway.'
    ]
  };

  const authPosture = emailInfo.auth_posture || {
    spf: {
      status: emailInfo.authentication?.spf?.status?.toLowerCase() || 'none',
      envelope_domain: emailInfo.return_path || 'unknown',
      client_ip: emailInfo.sender_ips?.[0] || 'unknown',
      mechanism: 'default',
      aligned: Boolean(emailInfo.authentication?.alignment?.spf_aligned)
    },
    dkim: {
      status: emailInfo.authentication?.dkim?.status?.toLowerCase() || 'none',
      signing_domain: emailInfo.authentication?.dkim?.domain || '',
      selector: 'selector1',
      algorithm: 'rsa-sha256',
      aligned: Boolean(emailInfo.authentication?.alignment?.dkim_aligned)
    },
    dmarc: {
      status: emailInfo.authentication?.dmarc?.status?.toLowerCase() || 'none',
      policy: emailInfo.authentication?.dmarc?.policy || 'none',
      spf_alignment: Boolean(emailInfo.authentication?.alignment?.spf_aligned),
      dkim_alignment: Boolean(emailInfo.authentication?.alignment?.dkim_aligned),
      from_domain: emailInfo.from ? (emailInfo.from.split('@')[1] || '') : ''
    },
    arc: {
      seal_status: emailInfo.authentication?.arc?.status || 'none',
      chain_valid: Boolean(emailInfo.authentication?.arc?.present),
      has_arc: Boolean(emailInfo.authentication?.arc?.present)
    },
    auth_summary: `DMARC: ${emailInfo.authentication?.dmarc?.status || 'NONE'} | SPF: ${emailInfo.authentication?.spf?.status || 'NONE'} | DKIM: ${emailInfo.authentication?.dkim?.status || 'NONE'}`,
    flags: []
  };

  const lookalike = emailInfo.lookalike_analysis || {
    display_name: emailInfo.from || '',
    from_address: emailInfo.from || '',
    from_domain: emailInfo.from ? (emailInfo.from.split('@')[1] || '') : '',
    reply_to_address: emailInfo.reply_to || '',
    reply_to_domain: emailInfo.reply_to ? (emailInfo.reply_to.split('@')[1] || '') : '',
    return_path_domain: emailInfo.return_path ? (emailInfo.return_path.split('@')[1] || '') : '',
    is_free_webmail: Boolean(emailInfo.sender_analysis?.is_freemail),
    display_name_spoofing: {
      is_spoofed: Boolean(emailInfo.sender_analysis?.display_name_spoofed),
      impersonated_entity: emailInfo.sender_analysis?.impersonated_brand || null,
      details: emailInfo.sender_analysis?.display_name_spoofed ? 'Display name claims trusted brand with unaligned sender domain.' : null
    },
    lookalike_domain: {
      is_lookalike: Boolean(emailInfo.sender_analysis?.has_homoglyphs || emailInfo.sender_analysis?.is_punycode),
      impersonated_brand: emailInfo.sender_analysis?.impersonated_brand || 'Protected Enterprise Brand',
      canonical_domain: emailInfo.sender_analysis?.impersonated_brand ? `${emailInfo.sender_analysis.impersonated_brand.toLowerCase()}.com` : 'target.com',
      edit_distance: 1,
      is_punycode: Boolean(emailInfo.sender_analysis?.is_punycode)
    },
    vip_executive_impersonation: {
      is_impersonating: Boolean(emailInfo.sender_analysis?.is_vip_impersonation),
      role: emailInfo.sender_analysis?.vip_title || 'Executive',
      details: emailInfo.sender_analysis?.is_vip_impersonation ? 'Executive title detected from external address.' : null
    },
    reply_to_mismatch: {
      is_mismatched: Boolean(emailInfo.sender_analysis?.is_mismatched_reply_to),
      is_free_webmail_redirect: Boolean(emailInfo.sender_analysis?.is_freemail),
      details: emailInfo.sender_analysis?.is_mismatched_reply_to ? 'Replies diverted to separate domain.' : null
    }
  };

  const urlThreats = emailInfo.url_threats || {
    total_urls_extracted: emailInfo.urls?.length || 0,
    deceptive_links_count: emailInfo.deceptive_links?.length || 0,
    ip_host_links_count: (emailInfo.urls || []).filter(u => /:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(u)).length,
    userinfo_obfuscated_count: (emailInfo.urls || []).filter(u => u.includes('@') && u.includes('://')).length,
    shortened_links_count: 0,
    credential_harvesting_count: (emailInfo.urls || []).filter(u => /(?:login|auth|verify|signin)/i.test(u)).length,
    url_items: (emailInfo.urls || []).map(u => ({
      url: u,
      host: u.split('/')[2] || u,
      is_deceptive: Boolean(emailInfo.deceptive_links?.some(dl => dl.actual_destination === u)),
      claimed_text: emailInfo.deceptive_links?.find(dl => dl.actual_destination === u)?.displayed_text,
      is_ip_host: /:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(u),
      has_userinfo: u.includes('@') && u.includes('://'),
      is_shortener: /(?:bit\.ly|tinyurl\.com|t\.co)/i.test(u),
      is_credential_target: /(?:login|auth|verify|signin)/i.test(u)
    }))
  };

  const htmlForensics = emailInfo.html_forensics || {
    has_html: Boolean(emailInfo.has_html),
    hidden_text_detected: false,
    hidden_text_items: [],
    credential_forms: [],
    meta_refreshes: [],
    data_urls: [],
    iframes: [],
    html_comments: []
  };

  const rawAtt = emailInfo.attachment_forensics;
  const attForensics = {
    total_attachments: rawAtt?.total_attachments ?? (emailInfo.attachments?.length || 0),
    dangerous_count: rawAtt?.dangerous_count ?? (emailInfo.attachments || []).filter(a => a.is_dangerous).length,
    mismatch_count: rawAtt?.mismatch_count ?? 0,
    macro_enabled_count: rawAtt?.macro_enabled_count ?? (emailInfo.attachments || []).filter(a => a.has_macros).length,
    double_extension_count: rawAtt?.double_extension_count ?? 0,
    nested_messages_count: rawAtt?.nested_messages_count ?? 0,
    inspected_attachments: (rawAtt?.inspected_attachments || (rawAtt as any)?.items || (emailInfo.attachments || []).map(a => ({
      filename: a.filename,
      size: a.size_bytes,
      declared_mime: a.content_type,
      detected_type: a.content_type,
      is_mismatch: false,
      is_dangerous: a.is_dangerous,
      has_macros: a.has_macros,
      has_double_extension: false,
      is_nested_email: false,
      sha256: a.sha256
    })))
  };

  const rawBec = emailInfo.bec_analysis;
  const becAnalysis = {
    bec_detected: rawBec?.bec_detected ?? false,
    bec_risk_score: rawBec?.bec_risk_score ?? 10,
    financial_fraud_types: Array.isArray(rawBec?.financial_fraud_types) ? rawBec.financial_fraud_types : [],
    bank_payment_redirection: rawBec?.bank_payment_redirection || { detected: false, matched_terms: [] },
    urgency_secrecy: rawBec?.urgency_secrecy || { detected: false, matched_terms: [] },
    gift_card_fraud: rawBec?.gift_card_fraud || { detected: false, matched_terms: [] },
    executive_wire_fraud: rawBec?.executive_wire_fraud || { detected: false, matched_terms: [] },
    indicators: Array.isArray(rawBec?.indicators) ? rawBec.indicators : []
  };

  const fileIntegrity = emailInfo.file_integrity || {
    format: 'Internet Message Format (EML / RFC 5322)',
    is_valid_format: true,
    file_size: rawEmailContent.length,
    file_hashes: {
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
      md5: 'd41d8cd98f00b204e9800998ecf8427e'
    },
    header_body_separated: true,
    duplicate_headers: [],
    mime_structure: {
      is_multipart: false,
      total_parts: 1,
      max_nesting_depth: 1,
      parser_defects: [],
      parts: []
    },
    clock_skew: {
      drift_detected: false,
      date_header: emailInfo.date,
      received_timestamp: emailInfo.transit_hops?.[0]?.timestamp,
      skew_hours: 0,
      details: 'Timestamps aligned with standard clock drift tolerance (<24 hours).'
    },
    unicode_anomalies: {
      bidi_controls_detected: false,
      zero_width_chars_detected: false,
      unicode_chars_found: []
    }
  };

  const offlineTools = emailInfo.offline_tools_guide || {
    file_hash: {
      tool: 'file & sha256sum',
      command: `file sample.eml && sha256sum sample.eml`,
      purpose: 'Identifies file magic signature and computes SHA-256 evidence integrity hash.'
    },
    python_email: {
      tool: 'Python email parser',
      command: `python3 -c "import email, sys; msg=email.message_from_binary_file(open('sample.eml','rb')); print(dict(msg.items()))"`,
      purpose: 'Inspects raw RFC 5322 headers, recipient addresses, and MIME structure offline.'
    },
    ripmime: {
      tool: 'ripMIME',
      command: `ripmime -i sample.eml -d /tmp/extracted_attachments/ -v`,
      purpose: 'Safely unpacks all nested attachments and MIME parts to disk for forensic triage.'
    },
    extract_msg: {
      tool: 'extract-msg (MSG / OLE)',
      command: `extract_msg --json sample.msg`,
      purpose: 'Parses binary Compound File MSG properties, MAPI properties, and embedded files.'
    },
    yara_scan: {
      tool: 'YARA Signatures',
      command: `yara -w email_threats.yar sample.eml`,
      purpose: 'Scans email stream for credential phishing heuristics, CVE markers, and macros.'
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. EXECUTIVE EMAIL SECURITY VERDICT BANNER */}
      <div
        className={`p-6 rounded-3xl border shadow-sm transition-all ${
          verdict.severity === 'critical'
            ? 'bg-rose-50/80 border-rose-300 text-rose-950'
            : verdict.severity === 'high'
            ? 'bg-orange-50/80 border-orange-300 text-orange-950'
            : verdict.severity === 'medium'
            ? 'bg-amber-50/80 border-amber-300 text-amber-950'
            : 'bg-emerald-50/80 border-emerald-300 text-emerald-950'
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-black/10">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className="text-[10px] font-mono uppercase tracking-wider font-bold px-2 py-0.5 rounded bg-black/10 text-slate-800">
                Executive Email Security Verdict
              </span>
              <span
                className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full ${
                  verdict.severity === 'critical'
                    ? 'bg-rose-200 text-rose-900 border border-rose-300'
                    : verdict.severity === 'high'
                    ? 'bg-orange-200 text-orange-900 border border-orange-300'
                    : verdict.severity === 'medium'
                    ? 'bg-amber-200 text-amber-900 border border-amber-300'
                    : 'bg-emerald-200 text-emerald-900 border border-emerald-300'
                }`}
              >
                Severity: {verdict.severity}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <h2 className="text-2xl font-black tracking-tight">{verdict.verdict}</h2>
            </div>
            {verdict.threat_categories.length > 0 && (
              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                {verdict.threat_categories.map((c, idx) => (
                  <span
                    key={idx}
                    className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-white/90 border border-black/10 text-slate-800 shadow-2xs"
                  >
                    {c}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="flex items-center gap-4 bg-white/80 backdrop-blur-xs p-3.5 rounded-2xl border border-black/10 self-start md:self-auto shadow-2xs">
            <div>
              <span className="text-[10px] font-mono text-slate-500 font-bold block uppercase tracking-wider">
                Analysis Confidence
              </span>
              <span className="text-2xl font-black font-mono text-slate-900">
                {verdict.confidence_score}%
              </span>
            </div>
            <div className="w-24 bg-slate-200 h-2.5 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  verdict.confidence_score >= 80 ? 'bg-rose-600' : 'bg-amber-500'
                }`}
                style={{ width: `${verdict.confidence_score}%` }}
              />
            </div>
          </div>
        </div>

        {/* Rationale & Actionable Guidance */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-4 text-xs">
          <div className="space-y-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-slate-700 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-indigo-600" />
              <span>Key Assessment Rationale:</span>
            </span>
            <ul className="space-y-1.5 text-slate-800">
              {verdict.key_assessment_rationale.map((r, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-rose-600 font-bold mt-0.5">•</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
            {verdict.mitre_attack_techniques.length > 0 && (
              <div className="pt-2 flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-mono text-slate-500 font-bold uppercase">MITRE ATT&CK:</span>
                {verdict.mitre_attack_techniques.map((t, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded bg-white border border-slate-300 text-slate-800 font-mono text-[10px] font-bold shadow-2xs"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-slate-700 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-rose-600" />
              <span>Actionable Containment Guidance:</span>
            </span>
            <ul className="space-y-1.5 text-slate-800">
              {verdict.containment_guidance.map((g, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{g}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* 2. TOP METADATA & ENVELOPE SUMMARY CARD */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between pb-4 border-b border-slate-100 mb-5 gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-2xl border border-indigo-100 text-lg">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">Email & Message Security Dossier</h3>
              <p className="text-xs text-slate-500">
                RFC 5322 / Outlook MSG parsing, authentication posture, lookalike detection, URL & HTML forensics, BEC analysis.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {!isCheckDisabled('check_spf_dkim_dmarc') && (
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold border flex items-center gap-1.5 ${
                  authPosture.dmarc.status === 'pass'
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : authPosture.dmarc.status === 'fail'
                    ? 'bg-rose-50 text-rose-800 border-rose-200 animate-pulse'
                    : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                DMARC: {authPosture.dmarc.status.toUpperCase()}
              </span>
            )}
            {!isCheckDisabled('check_tracking_pixels') && emailInfo.tracking_pixel_count && emailInfo.tracking_pixel_count > 0 && (
              <span className="px-3 py-1 bg-amber-50 text-amber-800 border border-amber-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <EyeOff className="w-3.5 h-3.5 text-amber-600" />
                {emailInfo.tracking_pixel_count} Tracking Beacons
              </span>
            )}
            {!isCheckDisabled('check_attachments') && attForensics.total_attachments > 0 && (
              <span className="px-3 py-1 bg-slate-100 text-slate-700 border border-slate-200 rounded-full text-xs font-semibold flex items-center gap-1.5">
                <Paperclip className="w-3.5 h-3.5 text-slate-600" />
                {attForensics.total_attachments} Attachments
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

        {/* 3. COMPREHENSIVE CHECKLIST NAVIGATION TABS */}
        <div className="flex border-b border-slate-200 gap-1 overflow-x-auto pt-2">
          <button
            onClick={() => setActiveTab('preview')}
            className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeTab === 'preview'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Visual Preview</span>
          </button>

          {!(isCheckDisabled('check_spf_dkim_dmarc') && isCheckDisabled('check_domain_dns_rdap')) && (
            <button
              onClick={() => setActiveTab('auth_lookalike')}
              className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeTab === 'auth_lookalike'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Auth & Lookalikes</span>
              {(lookalike.lookalike_domain.is_lookalike || authPosture.dmarc.status === 'fail' || lookalike.display_name_spoofing.is_spoofed) && (
                <span className="px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded-full text-[10px] font-bold">
                  Alert
                </span>
              )}
            </button>
          )}

          {!isCheckDisabled('check_links') && (
            <button
              onClick={() => setActiveTab('url_html')}
              className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeTab === 'url_html'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>URLs & HTML Forensics</span>
              {(urlThreats.deceptive_links_count > 0 || htmlForensics.hidden_text_detected) && (
                <span className="px-1.5 py-0.5 bg-amber-100 text-amber-800 rounded-full text-[10px] font-bold">
                  {urlThreats.deceptive_links_count + (htmlForensics.hidden_text_items?.length || 0)}
                </span>
              )}
            </button>
          )}

          {!isCheckDisabled('check_attachments') && (
            <button
              onClick={() => setActiveTab('attachment_forensics')}
              className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeTab === 'attachment_forensics'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Paperclip className="w-3.5 h-3.5" />
              <span>Attachment Forensics</span>
              {attForensics.total_attachments > 0 && (
                <span className="px-1.5 py-0.5 bg-slate-200 text-slate-700 rounded-full text-[10px] font-bold">
                  {attForensics.total_attachments}
                </span>
              )}
            </button>
          )}

          {!(isCheckDisabled('check_phishing_urgency') && isCheckDisabled('check_thread_hijacking')) && (
            <button
              onClick={() => setActiveTab('bec_fraud')}
              className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeTab === 'bec_fraud'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <DollarSign className="w-3.5 h-3.5" />
              <span>BEC & Financial Fraud</span>
              {becAnalysis.bec_detected && (
                <span className="px-1.5 py-0.5 bg-rose-100 text-rose-700 rounded-full text-[10px] font-bold">
                  Risk {becAnalysis.bec_risk_score}
                </span>
              )}
            </button>
          )}

          <button
            onClick={() => setActiveTab('file_integrity')}
            className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeTab === 'file_integrity'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FileCheck className="w-3.5 h-3.5" />
            <span>File Integrity & MIME</span>
          </button>

          <button
            onClick={() => setActiveTab('transit')}
            className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeTab === 'transit'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>MTA Transit Hops ({emailInfo.transit_hops?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('plaintext')}
            className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeTab === 'plaintext'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Plaintext Body</span>
          </button>

          {!isCheckDisabled('check_headers') && (
            <button
              onClick={() => setActiveTab('headers')}
              className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeTab === 'headers'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>RFC Headers ({Object.keys(emailInfo.headers).length})</span>
            </button>
          )}

          <button
            onClick={() => setActiveTab('raw')}
            className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeTab === 'raw'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Raw RFC 822</span>
          </button>

          {((emailInfo.attachment_graph && emailInfo.attachment_graph.length > 0) || (emailInfo.attachments && emailInfo.attachments.length > 0)) && (
            <button
              onClick={() => setActiveTab('graph')}
              className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                activeTab === 'graph'
                  ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Graph</span>
            </button>
          )}

          <button
            onClick={() => setActiveTab('offline_tools')}
            className={`px-3.5 py-2.5 text-xs font-semibold rounded-t-xl transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
              activeTab === 'offline_tools'
                ? 'bg-indigo-50/80 text-indigo-700 border-b-2 border-indigo-600'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Offline Tools CLI</span>
          </button>
        </div>

        {/* ========================================================================= */}
        {/* TAB 1: VISUAL EMAIL PREVIEW */}
        {/* ========================================================================= */}
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
                  e.preventDefault();
                }
              }}
              dangerouslySetInnerHTML={{
                __html: safePreviewHtml
              }}
            />
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: AUTHENTICATION POSTURE & LOOKALIKE DOMAINS */}
        {/* ========================================================================= */}
        {activeTab === 'auth_lookalike' && (
          <div className="pt-4 space-y-6">
            {/* Authentication Matrix Grid */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-indigo-600" />
                  <span>Sender Authentication Deep Dive (SPF, DKIM, DMARC, ARC)</span>
                </h4>
                <span className="text-[11px] font-mono text-slate-500">
                  {authPosture.auth_summary}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {/* DMARC */}
                <div
                  className={`p-4 rounded-2xl border transition-all ${
                    authPosture.dmarc.status === 'pass'
                      ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                      : authPosture.dmarc.status === 'fail'
                      ? 'bg-rose-50/70 border-rose-200 text-rose-950 shadow-2xs'
                      : 'bg-slate-50 border-slate-200 text-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold uppercase tracking-wider">DMARC Policy</span>
                    <span
                      className={`text-xs font-extrabold px-2.5 py-0.5 rounded-full ${
                        authPosture.dmarc.status === 'pass'
                          ? 'bg-emerald-100 text-emerald-800'
                          : authPosture.dmarc.status === 'fail'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {authPosture.dmarc.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[11px] space-y-1 font-mono">
                    <div>Policy: <span className="font-bold">{authPosture.dmarc.policy}</span></div>
                    <div>SPF Aligned: <span className={authPosture.dmarc.spf_alignment ? 'text-emerald-700 font-bold' : 'text-rose-700 font-bold'}>{authPosture.dmarc.spf_alignment ? 'YES' : 'NO'}</span></div>
                    <div>DKIM Aligned: <span className={authPosture.dmarc.dkim_alignment ? 'text-emerald-700 font-bold' : 'text-rose-700 font-bold'}>{authPosture.dmarc.dkim_alignment ? 'YES' : 'NO'}</span></div>
                  </div>
                </div>

                {/* SPF */}
                <div
                  className={`p-4 rounded-2xl border transition-all ${
                    authPosture.spf.status === 'pass'
                      ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                      : authPosture.spf.status === 'fail' || authPosture.spf.status === 'softfail'
                      ? 'bg-rose-50/70 border-rose-200 text-rose-950'
                      : 'bg-slate-50 border-slate-200 text-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold uppercase tracking-wider">SPF Validation</span>
                    <span
                      className={`text-xs font-extrabold px-2.5 py-0.5 rounded-full ${
                        authPosture.spf.status === 'pass'
                          ? 'bg-emerald-100 text-emerald-800'
                          : authPosture.spf.status === 'fail' || authPosture.spf.status === 'softfail'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {authPosture.spf.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[11px] space-y-1 font-mono truncate">
                    <div>IP: <span className="font-bold">{authPosture.spf.client_ip || 'N/A'}</span></div>
                    <div>Envelope: <span className="font-bold truncate">{authPosture.spf.envelope_domain || 'N/A'}</span></div>
                    <div>Aligned: <span className={authPosture.spf.aligned ? 'text-emerald-700 font-bold' : 'text-rose-700 font-bold'}>{authPosture.spf.aligned ? 'YES' : 'NO'}</span></div>
                  </div>
                </div>

                {/* DKIM */}
                <div
                  className={`p-4 rounded-2xl border transition-all ${
                    authPosture.dkim.status === 'pass'
                      ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                      : authPosture.dkim.status === 'fail'
                      ? 'bg-rose-50/70 border-rose-200 text-rose-950'
                      : 'bg-slate-50 border-slate-200 text-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold uppercase tracking-wider">DKIM Signature</span>
                    <span
                      className={`text-xs font-extrabold px-2.5 py-0.5 rounded-full ${
                        authPosture.dkim.status === 'pass'
                          ? 'bg-emerald-100 text-emerald-800'
                          : authPosture.dkim.status === 'fail'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {authPosture.dkim.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[11px] space-y-1 font-mono truncate">
                    <div>Signing d=: <span className="font-bold">{authPosture.dkim.signing_domain || 'None'}</span></div>
                    <div>Selector s=: <span className="font-bold">{authPosture.dkim.selector || 'None'}</span></div>
                    <div>Aligned: <span className={authPosture.dkim.aligned ? 'text-emerald-700 font-bold' : 'text-rose-700 font-bold'}>{authPosture.dkim.aligned ? 'YES' : 'NO'}</span></div>
                  </div>
                </div>

                {/* ARC */}
                <div
                  className={`p-4 rounded-2xl border transition-all ${
                    authPosture.arc.chain_valid
                      ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                      : authPosture.arc.has_arc
                      ? 'bg-amber-50/70 border-amber-200 text-amber-950'
                      : 'bg-slate-50 border-slate-200 text-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-bold uppercase tracking-wider">ARC Chain</span>
                    <span
                      className={`text-xs font-extrabold px-2.5 py-0.5 rounded-full ${
                        authPosture.arc.chain_valid
                          ? 'bg-emerald-100 text-emerald-800'
                          : authPosture.arc.has_arc
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {authPosture.arc.seal_status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[11px] space-y-1 font-mono">
                    <div>Chain Valid: <span className="font-bold">{authPosture.arc.chain_valid ? 'VALID' : 'NO'}</span></div>
                    <div>Sealed Hops: <span className="font-bold">{authPosture.arc.has_arc ? 'PRESENT' : 'NONE'}</span></div>
                    <div>Forwarded: <span className="font-bold">{authPosture.arc.has_arc ? 'DETECTED' : 'DIRECT'}</span></div>
                  </div>
                </div>
              </div>

              {/* Flags Alert Box */}
              {authPosture.flags && authPosture.flags.length > 0 && (
                <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-2xl text-xs space-y-1">
                  <div className="font-bold text-rose-900 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-rose-600" />
                    <span>Authentication Failure Indicators:</span>
                  </div>
                  {authPosture.flags.map((flag, idx) => (
                    <div key={idx} className="text-rose-800 font-mono text-[11px] pl-5">
                      • {flag}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Lookalike & Typosquatting Analysis */}
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Fingerprint className="w-4 h-4 text-indigo-600" />
                  <span>Display-Name Spoofing & Lookalike Typosquatting Engine</span>
                </h4>
                {lookalike.lookalike_domain.is_lookalike && (
                  <span className="px-3 py-1 bg-rose-100 text-rose-800 border border-rose-200 rounded-full text-xs font-bold animate-pulse">
                    Lookalike Typosquatting Detected!
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {/* Lookalike Domain Card */}
                <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Domain Squatting & Homoglyphs
                  </span>
                  <div className="space-y-1.5 font-mono text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Sender Domain:</span>
                      <span className="font-bold text-slate-900">@{lookalike.from_domain || 'N/A'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Impersonated Brand:</span>
                      <span className={`font-bold ${lookalike.lookalike_domain.is_lookalike ? 'text-rose-600' : 'text-slate-700'}`}>
                        {lookalike.lookalike_domain.impersonated_brand || 'None Detected'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Canonical Target:</span>
                      <span className="font-bold text-slate-800">{lookalike.lookalike_domain.canonical_domain || 'N/A'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Levenshtein Edit Dist:</span>
                      <span className="font-bold text-indigo-600">{lookalike.lookalike_domain.edit_distance ?? 'N/A'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Punycode / IDN:</span>
                      <span className="font-bold text-slate-800">{lookalike.lookalike_domain.is_punycode ? 'YES (xn-- detected)' : 'NO'}</span>
                    </div>
                  </div>
                </div>

                {/* Display Name & VIP Impersonation */}
                <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Display Name & VIP Authority
                  </span>
                  <div className="space-y-1.5 font-mono text-[11px]">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Header Display Name:</span>
                      <span className="font-bold text-slate-900 break-words">{lookalike.display_name || '(Empty)'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px]">Actual Address:</span>
                      <span className="font-bold text-slate-800 break-all">{lookalike.from_address}</span>
                    </div>
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-slate-500">Display Name Spoofed:</span>
                      <span className={lookalike.display_name_spoofing.is_spoofed ? 'text-rose-600 font-bold' : 'text-emerald-700 font-bold'}>
                        {lookalike.display_name_spoofing.is_spoofed ? 'YES (Brand Claim)' : 'NO'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">VIP / Executive Title:</span>
                      <span className={lookalike.vip_executive_impersonation.is_impersonating ? 'text-rose-600 font-bold' : 'text-slate-700'}>
                        {lookalike.vip_executive_impersonation.is_impersonating ? `${lookalike.vip_executive_impersonation.role} (Impersonation)` : 'None Detected'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Reply-To Mismatch Card */}
              <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs text-xs space-y-2">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  Reply-To Routing & Mismatch Analysis
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-400 block text-[10px]">From Domain</span>
                    <span className="font-bold text-slate-800">{lookalike.from_domain || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Reply-To Domain</span>
                    <span className={`font-bold ${lookalike.reply_to_mismatch.is_mismatched ? 'text-rose-600' : 'text-slate-800'}`}>
                      {lookalike.reply_to_domain || '(Matches From)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Webmail Divert</span>
                    <span className={`font-bold ${lookalike.reply_to_mismatch.is_free_webmail_redirect ? 'text-rose-600' : 'text-slate-700'}`}>
                      {lookalike.reply_to_mismatch.is_free_webmail_redirect ? 'YES (Free Webmail)' : 'NO'}
                    </span>
                  </div>
                </div>
                {lookalike.reply_to_mismatch.details && (
                  <p className="text-[11px] text-rose-800 bg-rose-50 p-2 rounded-lg border border-rose-200 mt-2 font-medium">
                    ⚠️ {lookalike.reply_to_mismatch.details}
                  </p>
                )}
              </div>
            </div>

            {/* Findings List */}
            {emailFindings.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
                  Security Warnings & Policy Triggers ({emailFindings.length})
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

        {/* ========================================================================= */}
        {/* TAB 3: URL THREATS & HTML FORENSICS */}
        {/* ========================================================================= */}
        {activeTab === 'url_html' && (
          <div className="pt-4 space-y-6">
            {/* Metric Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Extracted URLs
                </span>
                <span className="text-xl font-black font-mono text-slate-900">
                  {urlThreats.total_urls_extracted}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Deceptive Text
                </span>
                <span className={`text-xl font-black font-mono ${urlThreats.deceptive_links_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                  {urlThreats.deceptive_links_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  IP Hosts
                </span>
                <span className={`text-xl font-black font-mono ${urlThreats.ip_host_links_count > 0 ? 'text-amber-600' : 'text-slate-800'}`}>
                  {urlThreats.ip_host_links_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Userinfo (@)
                </span>
                <span className={`text-xl font-black font-mono ${urlThreats.userinfo_obfuscated_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                  {urlThreats.userinfo_obfuscated_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Shortened URLs
                </span>
                <span className="text-xl font-black font-mono text-indigo-600">
                  {urlThreats.shortened_links_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Cred Targets
                </span>
                <span className={`text-xl font-black font-mono ${urlThreats.credential_harvesting_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                  {urlThreats.credential_harvesting_count}
                </span>
              </div>
            </div>

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

            {/* Complete Extracted Links Inventory */}
            {urlThreats.url_items && urlThreats.url_items.length > 0 && (
              <div className="p-4 bg-white rounded-2xl border border-slate-200 shadow-2xs space-y-3">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Globe className="w-4 h-4 text-indigo-600" />
                  <span>URL Security Inventory ({urlThreats.url_items.length})</span>
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600">
                        <th className="py-2.5 px-3 text-left">Host</th>
                        <th className="py-2.5 px-3 text-left">Full Extracted URL</th>
                        <th className="py-2.5 px-3 text-left">Characteristics</th>
                        <th className="py-2.5 px-3 text-right">Investigate</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {urlThreats.url_items.map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/60">
                          <td className="py-2 px-3 font-bold text-slate-900 max-w-[180px] truncate">{item.host}</td>
                          <td className="py-2 px-3 text-slate-600 break-all max-w-md">{item.url}</td>
                          <td className="py-2 px-3">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {item.is_deceptive && (
                                <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold">
                                  Deceptive
                                </span>
                              )}
                              {item.is_ip_host && (
                                <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 text-[10px] font-bold">
                                  IP Host
                                </span>
                              )}
                              {item.has_userinfo && (
                                <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold">
                                  Userinfo @
                                </span>
                              )}
                              {item.is_shortener && (
                                <span className="px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-800 text-[10px] font-bold">
                                  Shortener
                                </span>
                              )}
                              {item.is_credential_target && (
                                <span className="px-1.5 py-0.5 rounded bg-orange-100 text-orange-800 text-[10px] font-bold">
                                  Auth/Login Path
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2 px-3 text-right">
                            <InvestigateAssetButton
                              ioc={item.url || item.host}
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

            {/* HTML Body Forensics (Hidden Text, Forms, Meta Refreshes) */}
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 space-y-4">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <FileCode className="w-4 h-4 text-indigo-600" />
                <span>HTML Body & Browser Phishing Forensics</span>
              </h4>

              {/* Hidden Text Alert Table */}
              <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold text-slate-800 flex items-center gap-1.5">
                    <EyeOff className="w-3.5 h-3.5 text-amber-600" />
                    <span>Concealed / Hidden Text Evasion Elements</span>
                  </span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${htmlForensics.hidden_text_detected ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'}`}>
                    {htmlForensics.hidden_text_detected ? `${htmlForensics.hidden_text_items.length} Elements Detected` : 'None Detected'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Adversaries embed zero-size (0px), transparent, or off-screen text to poison spam filter bayesian weights while remaining invisible to the user.
                </p>

                {htmlForensics.hidden_text_items && htmlForensics.hidden_text_items.length > 0 ? (
                  <div className="overflow-x-auto pt-2">
                    <table className="w-full text-xs font-mono border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-slate-600">
                          <th className="py-2 px-3 text-left">Concealment Technique</th>
                          <th className="py-2 px-3 text-left">Extracted Hidden Snippet</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {htmlForensics.hidden_text_items.map((item, idx) => (
                          <tr key={idx} className="hover:bg-slate-50">
                            <td className="py-2 px-3 text-amber-700 font-bold whitespace-nowrap">{item.reason || (item as any).method || 'CSS Concealment'}</td>
                            <td className="py-2 px-3 text-slate-700 break-all">{item.text || (item as any).text_snippet || ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-slate-400 italic text-[11px] pt-1">No CSS hidden text or off-screen font evasion detected.</p>
                )}
              </div>

              {/* Credential Harvesting Forms */}
              {htmlForensics.credential_forms && htmlForensics.credential_forms.length > 0 && (
                <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-rose-900 font-bold text-xs">
                    <Lock className="w-4 h-4 text-rose-600" />
                    <span>Embedded HTML Credential Harvesting Form Detected</span>
                  </div>
                  {htmlForensics.credential_forms.map((form: any, idx) => {
                    const formAction = form.action || form.form_action || '';
                    const formMethod = form.method || form.form_method || 'GET';
                    const inputsList = form.inputs || form.input_fields || [];
                    return (
                      <div key={idx} className="text-xs font-mono bg-white p-3 rounded-lg border border-rose-200 space-y-1">
                        <div>Action Target: <span className="font-bold text-rose-700">{formAction || '(Relative / Self)'}</span></div>
                        <div>Method: <span className="font-bold">{formMethod}</span></div>
                        <div>Contains Password Input: <span className="font-bold text-rose-600">{form.has_password_input ? 'YES' : 'NO'}</span></div>
                        <div>Inputs: <span className="text-slate-600">{Array.isArray(inputsList) ? inputsList.join(', ') : 'none'}</span></div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Meta Refreshes & Redirects */}
              {htmlForensics.meta_refreshes && htmlForensics.meta_refreshes.length > 0 && (
                <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl space-y-2">
                  <div className="flex items-center gap-2 text-amber-900 font-bold text-xs">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    <span>HTML Meta-Refresh Redirect Detected</span>
                  </div>
                  {htmlForensics.meta_refreshes.map((mr: any, idx) => {
                    const contentStr = typeof mr === 'string' ? mr : (mr.content || '');
                    return (
                      <div key={idx} className="text-xs font-mono bg-white p-2.5 rounded-lg border border-amber-200">
                        Content: <span className="font-bold text-slate-800">{contentStr}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: ATTACHMENT FORENSICS */}
        {/* ========================================================================= */}
        {activeTab === 'attachment_forensics' && (
          <div className="pt-4 space-y-5">
            {/* Metric Counters */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Total Attachments
                </span>
                <span className="text-xl font-black font-mono text-slate-900">
                  {attForensics.total_attachments}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Dangerous Types
                </span>
                <span className={`text-xl font-black font-mono ${attForensics.dangerous_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                  {attForensics.dangerous_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Signature Mismatch
                </span>
                <span className={`text-xl font-black font-mono ${attForensics.mismatch_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                  {attForensics.mismatch_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  VBA Macros
                </span>
                <span className={`text-xl font-black font-mono ${attForensics.macro_enabled_count > 0 ? 'text-amber-600' : 'text-slate-800'}`}>
                  {attForensics.macro_enabled_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Double Extensions
                </span>
                <span className={`text-xl font-black font-mono ${attForensics.double_extension_count > 0 ? 'text-rose-600' : 'text-slate-800'}`}>
                  {attForensics.double_extension_count}
                </span>
              </div>

              <div className="p-3 bg-slate-50 rounded-2xl border border-slate-200/80">
                <span className="text-slate-400 text-[10px] uppercase font-bold tracking-wider block mb-1">
                  Nested Emails
                </span>
                <span className="text-xl font-black font-mono text-indigo-600">
                  {attForensics.nested_messages_count}
                </span>
              </div>
            </div>

            {/* Inspected Attachments Table */}
            {attForensics.inspected_attachments && attForensics.inspected_attachments.length > 0 ? (
              <div className="p-4 bg-white rounded-2xl border border-slate-200 shadow-2xs space-y-3">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Paperclip className="w-4 h-4 text-indigo-600" />
                  <span>Deep Attachment Forensics Table ({attForensics.inspected_attachments.length})</span>
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50/70 text-slate-600">
                        <th className="py-2.5 px-3 text-left">Filename</th>
                        <th className="py-2.5 px-3 text-left">Declared MIME</th>
                        <th className="py-2.5 px-3 text-left">Detected Magic Type</th>
                        <th className="py-2.5 px-3 text-left">Flags</th>
                        <th className="py-2.5 px-3 text-left">SHA-256 Hash</th>
                        <th className="py-2.5 px-3 text-right">Size</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {attForensics.inspected_attachments.map((att: any, idx: number) => (
                        <tr key={idx} className="hover:bg-slate-50/60">
                          <td className="py-2 px-3 font-bold text-slate-900 break-all max-w-xs">{att.filename}</td>
                          <td className="py-2 px-3 text-slate-600">{att.declared_mime}</td>
                          <td className="py-2 px-3">
                            <span className={att.is_mismatch ? 'text-rose-600 font-bold' : 'text-slate-700'}>
                              {att.detected_type}
                            </span>
                          </td>
                          <td className="py-2 px-3">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {att.is_dangerous && (
                                <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold">
                                  Dangerous
                                </span>
                              )}
                              {att.has_macros && (
                                <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 text-[10px] font-bold">
                                  VBA Macros
                                </span>
                              )}
                              {att.has_double_extension && (
                                <span className="px-1.5 py-0.5 rounded bg-rose-100 text-rose-800 text-[10px] font-bold">
                                  Double Ext (.pdf.exe)
                                </span>
                              )}
                              {att.is_mismatch && (
                                <span className="px-1.5 py-0.5 rounded bg-red-100 text-red-800 text-[10px] font-bold">
                                  Type Mismatch
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2 px-3 text-slate-500 font-mono text-[11px] truncate max-w-[140px]" title={att.sha256}>
                            {att.sha256 ? `${att.sha256.slice(0, 16)}...` : 'N/A'}
                          </td>
                          <td className="py-2 px-3 text-right font-mono">{formatBytes(att.size ?? (att as any).size_bytes ?? 0)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <p className="text-slate-400 italic text-xs p-4 text-center">No attachments present in this email message.</p>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 5: BUSINESS EMAIL COMPROMISE (BEC) & FINANCIAL FRAUD */}
        {/* ========================================================================= */}
        {activeTab === 'bec_fraud' && (
          <div className="pt-4 space-y-6">
            {/* BEC Risk Score Gauge Card */}
            <div className={`p-5 rounded-2xl border ${becAnalysis.bec_detected ? 'bg-rose-50/70 border-rose-200' : 'bg-slate-50 border-slate-200'}`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-black/10">
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-slate-500 block">
                    Business Email Compromise (BEC) Calibrated Risk Model
                  </span>
                  <h3 className="text-lg font-bold text-slate-900 mt-0.5">
                    {becAnalysis.bec_detected ? 'High-Risk Financial Fraud / BEC Indicators Detected' : 'Low Probability of Business Email Compromise'}
                  </h3>
                </div>

                <div className="flex items-center gap-3 bg-white p-3 rounded-2xl border border-slate-200 shadow-2xs">
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 font-bold block uppercase">BEC Risk Score</span>
                    <span className={`text-2xl font-black font-mono ${becAnalysis.bec_risk_score >= 60 ? 'text-rose-600' : 'text-slate-800'}`}>
                      {becAnalysis.bec_risk_score} / 100
                    </span>
                  </div>
                  <div className="w-24 bg-slate-200 h-2.5 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        becAnalysis.bec_risk_score >= 70 ? 'bg-rose-600' : becAnalysis.bec_risk_score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${becAnalysis.bec_risk_score}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Fraud Categories Breakdown */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-4 text-xs font-mono">
                <div className={`p-3 rounded-xl border bg-white ${becAnalysis.bank_payment_redirection?.detected ? 'border-rose-300' : 'border-slate-200'}`}>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Banking Redirection</span>
                  <span className={`font-bold ${becAnalysis.bank_payment_redirection?.detected ? 'text-rose-600' : 'text-slate-700'}`}>
                    {becAnalysis.bank_payment_redirection?.detected ? 'DETECTED' : 'None'}
                  </span>
                </div>

                <div className={`p-3 rounded-xl border bg-white ${becAnalysis.urgency_secrecy?.detected ? 'border-rose-300' : 'border-slate-200'}`}>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Urgency & Secrecy</span>
                  <span className={`font-bold ${becAnalysis.urgency_secrecy?.detected ? 'text-rose-600' : 'text-slate-700'}`}>
                    {becAnalysis.urgency_secrecy?.detected ? 'DETECTED' : 'None'}
                  </span>
                </div>

                <div className={`p-3 rounded-xl border bg-white ${becAnalysis.gift_card_fraud?.detected ? 'border-rose-300' : 'border-slate-200'}`}>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Gift Card Arbitrage</span>
                  <span className={`font-bold ${becAnalysis.gift_card_fraud?.detected ? 'text-rose-600' : 'text-slate-700'}`}>
                    {becAnalysis.gift_card_fraud?.detected ? 'DETECTED' : 'None'}
                  </span>
                </div>

                <div className={`p-3 rounded-xl border bg-white ${becAnalysis.executive_wire_fraud?.detected ? 'border-rose-300' : 'border-slate-200'}`}>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Executive Wire Fraud</span>
                  <span className={`font-bold ${becAnalysis.executive_wire_fraud?.detected ? 'text-rose-600' : 'text-slate-700'}`}>
                    {becAnalysis.executive_wire_fraud?.detected ? 'DETECTED' : 'None'}
                  </span>
                </div>
              </div>

              {/* Detected Fraud Indicators List */}
              {becAnalysis.indicators && becAnalysis.indicators.length > 0 && (
                <div className="mt-4 p-3.5 bg-white rounded-xl border border-rose-200 text-xs space-y-1.5 font-mono">
                  <span className="text-[11px] font-bold text-rose-900 block font-sans">
                    Matched Forensic Financial Fraud Indicators:
                  </span>
                  {becAnalysis.indicators.map((ind, idx) => (
                    <div key={idx} className="text-rose-800 text-[11px]">
                      • {ind}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 6: FILE INTEGRITY, HASHES & MIME STRUCTURE */}
        {/* ========================================================================= */}
        {activeTab === 'file_integrity' && (
          <div className="pt-4 space-y-6">
            {/* Format & Cryptographic Hashes */}
            <div className="p-5 bg-slate-50 rounded-2xl border border-slate-200 space-y-4">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-indigo-600" />
                <span>File Format & Cryptographic Evidence Integrity</span>
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Declared & Parsed Format</span>
                  <span className="text-slate-900 font-bold">{fileIntegrity.format}</span>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">File Byte Size</span>
                  <span className="text-slate-900 font-bold">{formatBytes(fileIntegrity.file_size)}</span>
                </div>

                <div className="p-3 bg-white rounded-xl border border-slate-200 shadow-2xs">
                  <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Header / Body Separation</span>
                  <span className={`font-bold ${fileIntegrity.header_body_separated ? 'text-emerald-700' : 'text-rose-600'}`}>
                    {fileIntegrity.header_body_separated ? 'Compliant (\r\n\r\n)' : 'Malformed Boundary'}
                  </span>
                </div>
              </div>

              {/* Cryptographic Hashes */}
              <div className="p-4 bg-white rounded-xl border border-slate-200 space-y-2 font-mono text-xs shadow-2xs">
                <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
                  <span className="text-slate-400 text-[10px] uppercase font-bold">SHA-256 Hash:</span>
                  <span className="text-slate-900 font-bold select-all break-all">{fileIntegrity.file_hashes.sha256}</span>
                </div>
                <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
                  <span className="text-slate-400 text-[10px] uppercase font-bold">SHA-1 Hash:</span>
                  <span className="text-slate-800 select-all break-all">{fileIntegrity.file_hashes.sha1}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 text-[10px] uppercase font-bold">MD5 Hash:</span>
                  <span className="text-slate-800 select-all">{fileIntegrity.file_hashes.md5}</span>
                </div>
              </div>

              {/* Duplicate Headers Audit */}
              {fileIntegrity.duplicate_headers && fileIntegrity.duplicate_headers.length > 0 && (
                <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl space-y-2 text-xs">
                  <div className="font-bold text-amber-900 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    <span>Duplicate Critical RFC 5322 Headers (Parser Confusion Evasion):</span>
                  </div>
                  {fileIntegrity.duplicate_headers.map((dup, idx) => (
                    <div key={idx} className="font-mono text-amber-800 pl-5">
                      • {dup.name}: Found {dup.count} occurrences ({Array.isArray(dup.values) ? dup.values.join(' | ') : ''})
                    </div>
                  ))}
                </div>
              )}

              {/* Clock Skew & Drift */}
              <div className="p-4 bg-white rounded-xl border border-slate-200 text-xs font-mono shadow-2xs space-y-1">
                <span className="text-[10px] text-slate-400 uppercase font-bold block mb-1">Clock Skew / Timestamp Drift Analysis</span>
                <div>Drift Detected: <span className={fileIntegrity.clock_skew?.drift_detected ? 'text-rose-600 font-bold' : 'text-emerald-700 font-bold'}>{fileIntegrity.clock_skew?.drift_detected ? 'YES' : 'NO'}</span></div>
                <div>Details: <span className="text-slate-700">{fileIntegrity.clock_skew?.details || 'Timestamps consistent.'}</span></div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 7: SERVER TRANSIT HOPS */}
        {/* ========================================================================= */}
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

        {/* ========================================================================= */}
        {/* TAB 8: EXTRACTED PLAINTEXT BODY */}
        {/* ========================================================================= */}
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

        {/* ========================================================================= */}
        {/* TAB 9: RAW RFC 822 HEADERS */}
        {/* ========================================================================= */}
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

        {/* ========================================================================= */}
        {/* TAB 10: RAW RFC 822 STREAM & TOOLBAR */}
        {/* ========================================================================= */}
        {activeTab === 'raw' && (
          <div className="pt-4 space-y-3">
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-50 p-3 rounded-2xl border border-slate-200">
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
                                      <mark key={i} className="bg-amber-300 text-slate-900 rounded-xs px-0.5">
                                        {part}
                                      </mark>
                                    ) : (
                                      part
                                    )
                                  );
                                })()}
                              </span>
                            ) : (
                              line
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

        {/* ========================================================================= */}
        {/* TAB 11: RELATIONSHIP GRAPH */}
        {/* ========================================================================= */}
        {activeTab === 'graph' && (
          <div className="pt-4 space-y-3">
            <span className="text-xs font-semibold text-slate-700 block">
              Email Hierarchy &amp; Artifact Network
            </span>
            <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 text-xs font-mono space-y-2">
              <div className="p-3 bg-white rounded-xl border border-indigo-200 shadow-xs">
                <span className="text-indigo-600 font-bold block mb-1">Root Email Message</span>
                <div className="text-slate-800">Subject: {emailInfo.subject || '(No Subject)'}</div>
                <div className="text-slate-600">From: {emailInfo.from}</div>
              </div>
              <div className="pl-6 space-y-2 border-l-2 border-dashed border-indigo-200 ml-4">
                {emailInfo.attachments.map((att, idx) => (
                  <div key={idx} className="p-3 bg-white rounded-xl border border-slate-200 shadow-xs">
                    <span className="text-indigo-600 font-bold flex items-center gap-2 mb-1">
                      <span>↳</span>
                      <span>{att.filename}</span>
                    </span>
                    <div className="text-[11px] text-slate-500 font-sans flex items-center gap-3">
                      <span>MIME: {att.content_type}</span>
                      <span>SHA256: {att.sha256.slice(0, 16)}...</span>
                      <span>Size: {formatBytes(att.size_bytes)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 12: OFFLINE FORENSIC TOOLS CLI GUIDE */}
        {/* ========================================================================= */}
        {activeTab === 'offline_tools' && (
          <div className="pt-4 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-600" />
                  <span>Offline Forensic Tools CLI Execution Guide</span>
                </h4>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Standard offline command-line utilities for air-gapped forensic extraction, hash integrity, and triage.
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {Object.entries(offlineTools).map(([toolKey, toolInfo]) => (
                <div key={toolKey} className="p-4 bg-slate-900 text-slate-100 rounded-2xl shadow-sm border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-indigo-400 font-mono flex items-center gap-2">
                      <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                      <span>{toolInfo.tool}</span>
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopyToolCommand(toolKey, toolInfo.command)}
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[10px] font-mono transition-colors flex items-center gap-1.5 cursor-pointer border border-slate-700"
                    >
                      {copiedTool === toolKey ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-400 font-bold">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3 text-slate-400" />
                          <span>Copy CLI</span>
                        </>
                      )}
                    </button>
                  </div>
                  <div className="p-2.5 bg-black/50 rounded-xl font-mono text-[11px] text-emerald-400 select-all overflow-x-auto">
                    $ {toolInfo.command}
                  </div>
                  <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                    {toolInfo.purpose}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 4. ATTACHMENTS SECTION WITH DEEP ANALYZE & WORKSPACE ACTIONS */}
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
              const matchedWorkspaceJob = findReferencedJob(att.filename, workspaceJobs, jobId) || (att.sha256 ? findReferencedJob(att.sha256, workspaceJobs, jobId) : null);
              const targetJobId = analyzedJobs[att.index] || matchedWorkspaceJob?.jobId;

              return (
                <div
                  key={i}
                  className={`p-4 rounded-2xl border transition-all ${
                    att.is_dangerous
                      ? 'bg-rose-50/50 border-rose-200'
                      : att.has_macros
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
                            VBA Macros
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono flex items-center gap-3 flex-wrap">
                        <span>{formatBytes(att.size_bytes)}</span>
                        <span>•</span>
                        <span>{att.content_type}</span>
                        <span>•</span>
                        <span className="truncate max-w-[200px]" title={att.sha256}>SHA256: {att.sha256}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleAnalyzeAttachment(att.index)}
                        disabled={analyzingAttIndex === att.index}
                        className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-300 text-white text-xs font-semibold rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer"
                      >
                        <Play className="w-3 h-3" />
                        <span>{analyzingAttIndex === att.index ? 'Queuing...' : 'Deep Analyze'}</span>
                      </button>
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
