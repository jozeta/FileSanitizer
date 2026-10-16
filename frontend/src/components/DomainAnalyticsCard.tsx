import React, { useState, useEffect } from 'react';
import { DomainIntelligence } from '../types';
import { apiClient } from '../api/client';
import { InvestigateAssetButton } from './InvestigateAssetButton';
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
  Network,
  Lock,
  Radio,
  Layers,
  Terminal,
  Search,
  Shield,
  Activity,
  Zap,
  ArrowRight,
  Loader2,
  Mail,
  Archive,
  ExternalLink,
  CheckCircle,
  Key,
  ShieldCheck,
  FileCode,
  Flame,
  Bug,
  Compass,
  Code,
  CornerDownRight,
  FileText,
  GitCompare,
  Crosshair,
  Tag,
  AlertCircle,
  XCircle,
  ChevronDown,
  ChevronUp,
  Star,
  Cloud
} from 'lucide-react';

export const CLOUD_TAKEOVER_SIGNATURES = [
  {
    provider: 'AWS S3',
    serviceType: 'Object Storage / Static Website Hosting',
    cnamePattern: '*.s3.amazonaws.com, *.s3-website*.amazonaws.com',
    cnameRegex: '\\.s3(?:-website)?(?:-[a-z0-9-]+)?\\.amazonaws\\.com$',
    fingerprint: 'NoSuchBucket',
    unclaimedStatus: 'unclaimed_bucket',
    severity: 'high',
    remediation: 'Claim the S3 bucket in the matching AWS region or remove the dangling CNAME record immediately.'
  },
  {
    provider: 'GitHub Pages',
    serviceType: 'Static Site / Documentation Hosting',
    cnamePattern: '*.github.io',
    cnameRegex: '\\.github\\.io$',
    fingerprint: "There isn't a GitHub Pages site here",
    unclaimedStatus: 'unclaimed_repo',
    severity: 'high',
    remediation: 'Verify repository CNAME setting on GitHub or delete the dangling DNS CNAME record.'
  },
  {
    provider: 'Heroku',
    serviceType: 'Cloud Platform as a Service (PaaS)',
    cnamePattern: '*.herokudns.com, *.herokuapp.com',
    cnameRegex: '\\.(?:herokudns|herokuapp)\\.com$',
    fingerprint: 'No such app',
    unclaimedStatus: 'unclaimed_app',
    severity: 'high',
    remediation: 'Point CNAME to active Heroku application or remove the DNS record.'
  },
  {
    provider: 'Azure Web Apps',
    serviceType: 'Azure App Service / Web Hosting',
    cnamePattern: '*.azurewebsites.net',
    cnameRegex: '\\.azurewebsites\\.net$',
    fingerprint: '404 Web Site not found',
    unclaimedStatus: 'unclaimed_azure_app',
    severity: 'high',
    remediation: 'Bind custom domain in Azure portal or delete the unlinked CNAME record.'
  },
  {
    provider: 'Shopify',
    serviceType: 'E-Commerce Platform & Online Stores',
    cnamePattern: '*.myshopify.com',
    cnameRegex: '\\.myshopify\\.com$',
    fingerprint: 'Sorry, this shop is currently unavailable',
    unclaimedStatus: 'unclaimed_store',
    severity: 'medium',
    remediation: 'Verify Shopify custom domain mapping or remove stale DNS record.'
  },
  {
    provider: 'Zendesk',
    serviceType: 'Customer Support & Help Center Portal',
    cnamePattern: '*.zendesk.com',
    cnameRegex: '\\.zendesk\\.com$',
    fingerprint: 'Help Center Closed',
    unclaimedStatus: 'unclaimed_helpcenter',
    severity: 'medium',
    remediation: 'Re-link Zendesk help center or remove host mapping.'
  },
  {
    provider: 'Fastly',
    serviceType: 'Edge Cloud Content Delivery Network (CDN)',
    cnamePattern: '*.fastly.net',
    cnameRegex: '\\.fastly\\.net$',
    fingerprint: 'Fastly error: unknown domain',
    unclaimedStatus: 'unclaimed_cdn',
    severity: 'high',
    remediation: 'Configure service on Fastly or delete CNAME.'
  },
  {
    provider: 'Surge.sh',
    serviceType: 'Static Web Publishing',
    cnamePattern: '*.surge.sh',
    cnameRegex: '\\.surge\\.sh$',
    fingerprint: 'project not found',
    unclaimedStatus: 'unclaimed_surge_project',
    severity: 'high',
    remediation: 'Publish surge project under domain or remove CNAME.'
  }
];

interface DomainAnalyticsCardProps {
  domainInfo: DomainIntelligence;
  thumbnailUrl?: string;
  jobId?: string;
  onNavigateToJob?: (jobId: string) => void;
  disabledChecks?: string[];
}

export const DomainAnalyticsCard: React.FC<DomainAnalyticsCardProps> = ({
  domainInfo: initialDomainInfo,
  thumbnailUrl,
  jobId,
  onNavigateToJob,
  disabledChecks = []
}) => {
  const [domainInfo, setDomainInfo] = useState<DomainIntelligence>(initialDomainInfo);
  const [activeTab, setActiveTab] = useState<
    'overview' | 'normalisation' | 'takeover' | 'relations' | 'email_sec' | 'archive' | 'bgp_pdns' | 'recon' | 'surface' | 'tls' | 'dns' | 'web' | 'cti' | 'exposure' | 'vulnerabilities' | 'typosquatting'
  >('overview');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [subdomainSearch, setSubdomainSearch] = useState('');
  const [isScanningPorts, setIsScanningPorts] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [isScoreHovered, setIsScoreHovered] = useState<boolean>(false);

  // Attack Surface Subdomains Filtering State
  const [subdomainStatusFilter, setSubdomainStatusFilter] = useState<'all' | 'active' | 'unresolving'>('all');
  const [subdomainSourceFilter, setSubdomainSourceFilter] = useState<string>('all');
  const [subdomainViewMode, setSubdomainViewMode] = useState<'table' | 'grid'>('table');
  const [showUnresolvedExplanation, setShowUnresolvedExplanation] = useState<boolean>(true);
  const [sanSearch, setSanSearch] = useState<string>('');

  // Correlated Infrastructure Filtering State
  const [relationFilter, setRelationFilter] = useState<string>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('all');
  const [relationSearch, setRelationSearch] = useState<string>('');
  const [relationViewTab, setRelationViewTab] = useState<'direct' | 'shared' | 'all'>('direct');
  const [showSharedAccordion, setShowSharedAccordion] = useState<boolean>(false);

  // Advanced DNS Filtering State
  const [dnsFilter, setDnsFilter] = useState<string>('all');
  const [dnsSearch, setDnsSearch] = useState<string>('');

  // Web Fingerprint Headers Filter
  const [headerSearch, setHeaderSearch] = useState<string>('');

  // Typosquatting & Brand Defense Filter State
  const [typoFilter, setTypoFilter] = useState<'all' | 'resolving' | 'unregistered'>('all');
  const [typoSearch, setTypoSearch] = useState<string>('');

  // Web Exposure Filter State
  const [exposureCategoryFilter, setExposureCategoryFilter] = useState<string>('all');
  const [exposureSearch, setExposureSearch] = useState<string>('');

  // Cloud Provider Takeover Signatures Search & Filter State
  const [signatureSearch, setSignatureSearch] = useState<string>('');
  const [signatureProviderFilter, setSignatureProviderFilter] = useState<string>('all');

  // Enforce redirection away from disabled checks/tabs
  useEffect(() => {
    const disabledMap: Record<string, string[]> = {
      takeover: ['check_subdomains'],
      surface: ['check_subdomains'],
      email_sec: ['check_mx_reputation'],
      tls: ['check_ssl_tls_cert'],
      dns: ['check_dns_records'],
      cti: ['check_virustotal', 'virustotal_enabled'],
    };
    if (disabledChecks && disabledMap[activeTab]?.some(dc => disabledChecks.includes(dc))) {
      setActiveTab('overview');
    }
  }, [activeTab, disabledChecks]);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleTriggerActiveRecon = async () => {
    if (!jobId || isScanningPorts) return;
    setIsScanningPorts(true);
    setScanMessage('Executing authorized port scan, sensitive file prober, and vulnerability checks...');
    try {
      const res = await apiClient.triggerActiveRecon(jobId, true);
      if (res.success) {
        setDomainInfo(prev => ({
          ...prev,
          active_recon: res.active_recon || prev.active_recon,
          active_security_probes: res.active_security_probes || prev.active_security_probes,
          risk_scores: res.risk_scores || prev.risk_scores
        }));
        setScanMessage('Active security audit & vulnerability probes completed successfully!');
      }
    } catch (err: any) {
      setScanMessage(err.message || 'Active reconnaissance failed');
    } finally {
      setIsScanningPorts(false);
      setTimeout(() => setScanMessage(null), 4000);
    }
  };

  const puny = domainInfo.punycode_analysis;
  const whois = domainInfo.whois || {};
  const dns = domainInfo.dns_records || {};
  const advDns = domainInfo.advanced_dns;
  const net = (domainInfo.network || {}) as Record<string, any>;
  const asnProf = domainInfo.asn_profile;
  const tls = domainInfo.tls_profile;
  const web = domainInfo.web_fingerprint;
  const cti = domainInfo.threat_intelligence;
  const surface = domainInfo.attack_surface;
  const activeRecon = domainInfo.active_recon;
  const activeProbes = domainInfo.active_security_probes;
  const emailSec = domainInfo.email_security;
  const webArch = domainInfo.web_archive;
  const bgpRouting = domainInfo.bgp_routing;
  const pDns = domainInfo.passive_dns;
  const leakSearch = domainInfo.leak_search;
  const scores = domainInfo.risk_scores;
  const coHosted = domainInfo.co_hosted_domains || [];
  const relatedDomains = (domainInfo.related_domains || []) as Array<any>;
  const directAffiliates = (domainInfo.direct_affiliates || relatedDomains.filter(r => r.is_direct || r.connection_type === 'direct')) as Array<any>;
  const sharedNeighbors = (domainInfo.shared_infrastructure_neighbors || relatedDomains.filter(r => !r.is_direct && r.connection_type !== 'direct')) as Array<any>;
  const directCount = directAffiliates.length;
  const sharedCount = sharedNeighbors.length;

  const ownershipPivots = domainInfo.ownership_pivots;
  const fcrdns = domainInfo.fcrdns;
  const webExposure = domainInfo.web_exposure;
  const vulnIntel = domainInfo.vulnerability_intel;
  const revInfra = domainInfo.reverse_infrastructure;
  const typosquat = domainInfo.typosquatting;
  const trackingPivots = domainInfo.tracking_pivots;
  const snapshotDiff = domainInfo.snapshot_diff;

  // IP & Domain Checklist Forensics
  const checklistVerdict = domainInfo.checklist_verdict;
  const normalisation = domainInfo.indicator_normalisation;
  const takeoverAnalysis = domainInfo.subdomain_takeover_analysis;
  const dnsAudit = domainInfo.dns_configuration_audit;
  const emailPosture = domainInfo.email_domain_posture;
  const tlsForensics = domainInfo.tls_cert_forensics;
  const webExposureAudit = domainInfo.web_headers_and_exposure;

  // Filter subdomains for surface map with provenance & status awareness
  const filteredSubdomains = (surface?.subdomains || []).filter(s => {
    const q = subdomainSearch.toLowerCase();
    const matchesSearch = !q ||
      s.subdomain.toLowerCase().includes(q) ||
      (s.ips || []).some(ip => ip.toLowerCase().includes(q)) ||
      (s.discovered_from || '').toLowerCase().includes(q);
    const matchesStatus = subdomainStatusFilter === 'all' || s.status === subdomainStatusFilter;
    const matchesSource = subdomainSourceFilter === 'all' ||
      (s.discovered_from && s.discovered_from.toLowerCase().includes(subdomainSourceFilter.toLowerCase())) ||
      ((s.sources || []).some(src => src.toLowerCase().includes(subdomainSourceFilter.toLowerCase())));
    return matchesSearch && matchesStatus && matchesSource;
  });

  // Direct Affiliates Filtering (High-confidence cryptographic/ownership siblings)
  const filteredDirectAffiliates = directAffiliates.filter(r => {
    if (relationSearch && !r.domain.toLowerCase().includes(relationSearch.toLowerCase())) {
      return false;
    }
    if (confidenceFilter !== 'all' && r.confidence !== confidenceFilter) {
      return false;
    }
    if (relationFilter !== 'all' && !r.relationships.includes(relationFilter)) {
      return false;
    }
    return true;
  });

  // Shared Multi-Tenant Neighbors Filtering (Co-hosted on CDN/DDoS edge, public registrar NS)
  const filteredSharedNeighbors = sharedNeighbors.filter(r => {
    if (relationSearch && !r.domain.toLowerCase().includes(relationSearch.toLowerCase())) {
      return false;
    }
    if (confidenceFilter !== 'all' && r.confidence !== confidenceFilter) {
      return false;
    }
    if (relationFilter !== 'all' && !r.relationships.includes(relationFilter)) {
      return false;
    }
    return true;
  });

  // All Relations Filtering
  const filteredRelations = relatedDomains.filter(r => {
    if (relationSearch && !r.domain.toLowerCase().includes(relationSearch.toLowerCase())) {
      return false;
    }
    if (confidenceFilter !== 'all' && r.confidence !== confidenceFilter) {
      return false;
    }
    if (relationFilter !== 'all' && !r.relationships.includes(relationFilter)) {
      return false;
    }
    return true;
  });

  // Filtered Cloud Takeover Signatures
  const filteredSignatures = CLOUD_TAKEOVER_SIGNATURES.filter(sig => {
    const q = signatureSearch.toLowerCase();
    const matchesSearch = !q ||
      sig.provider.toLowerCase().includes(q) ||
      sig.serviceType.toLowerCase().includes(q) ||
      sig.cnamePattern.toLowerCase().includes(q) ||
      sig.fingerprint.toLowerCase().includes(q) ||
      sig.unclaimedStatus.toLowerCase().includes(q);
    const matchesProvider = signatureProviderFilter === 'all' || sig.provider === signatureProviderFilter;
    return matchesSearch && matchesProvider;
  });

  const getScoreColor = (level: string = 'clean') => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'text-rose-700 bg-rose-50 border-rose-200';
      case 'high':
        return 'text-amber-700 bg-amber-50 border-amber-200';
      case 'medium':
        return 'text-yellow-700 bg-yellow-50 border-yellow-200';
      case 'low':
        return 'text-blue-700 bg-blue-50 border-blue-200';
      default:
        return 'text-emerald-700 bg-emerald-50 border-emerald-200';
    }
  };

  const getConfidenceBadge = (conf: string) => {
    switch (conf) {
      case 'high':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300 font-bold';
      case 'medium':
        return 'bg-blue-100 text-blue-800 border-blue-200 font-medium';
      case 'low':
        return 'bg-slate-100 text-slate-600 border-slate-200';
      default:
        return 'bg-slate-100 text-slate-600 border-slate-200';
    }
  };

  return (
    <div className="bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden mb-6">
      {/* ----------------- TOP HERO HEADER ----------------- */}
      <div className="px-6 py-5 bg-gradient-to-r from-blue-50/90 via-slate-50 to-white border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-2.5 bg-blue-600 text-white rounded-xl shadow-xs">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-bold text-slate-900 tracking-tight">
                {domainInfo.target}
              </h3>
              {domainInfo.is_ip ? (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-purple-100 text-purple-800 border border-purple-200">
                  IP Asset
                </span>
              ) : (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-blue-100 text-blue-800 border border-blue-200">
                  Domain Infrastructure
                </span>
              )}
              {asnProf?.classification && (
                <span className="text-xs px-2 py-0.5 rounded-full font-mono bg-slate-100 text-slate-700 border border-slate-200">
                  {asnProf.classification}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 font-mono mt-0.5 flex items-center gap-2">
              <span>Canonical: {domainInfo.normalized_value || domainInfo.target}</span>
              {net?.ip && <span>• IP: {net.ip}</span>}
              {asnProf?.asn && <span>• {asnProf.asn}</span>}
            </p>
          </div>
        </div>

        {/* Quick Alert Badges */}
        <div className="flex items-center gap-2 flex-wrap">
          {puny?.is_homograph && (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300 animate-pulse">
              <ShieldAlert className="w-3.5 h-3.5 mr-1 text-rose-600" />
              Homograph Impersonation
            </span>
          )}
          {fcrdns && fcrdns.status === 'VALID' && (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
              <CheckCircle2 className="w-3.5 h-3.5 mr-1 text-emerald-600" />
              FCrDNS Valid
            </span>
          )}
          {fcrdns && fcrdns.status === 'MISMATCH' && (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300 animate-pulse">
              <AlertCircle className="w-3.5 h-3.5 mr-1 text-rose-600" />
              FCrDNS Mismatch
            </span>
          )}
          {vulnIntel?.cisa_kev_count ? (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-rose-100 text-rose-900 border border-rose-300">
              <Bug className="w-3.5 h-3.5 mr-1 text-rose-700" />
              {vulnIntel.cisa_kev_count} CISA KEV
            </span>
          ) : null}
          {typosquat?.has_live_impersonators && (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-300">
              <Crosshair className="w-3.5 h-3.5 mr-1 text-amber-600" />
              {typosquat.active_registered_count} Live Lookalikes
            </span>
          )}
          {webExposure?.robots_txt?.sensitive_paths_flagged && webExposure.robots_txt.sensitive_paths_flagged.length > 0 && (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-300">
              <FileText className="w-3.5 h-3.5 mr-1 text-amber-600" />
              {webExposure.robots_txt.sensitive_paths_flagged.length} Exposed Paths
            </span>
          )}
          {snapshotDiff?.has_historical_baseline && (snapshotDiff.total_changes_detected || 0) > 0 && (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-indigo-100 text-indigo-800 border border-indigo-300">
              <GitCompare className="w-3.5 h-3.5 mr-1 text-indigo-600" />
              {snapshotDiff.total_changes_detected} History Shifts
            </span>
          )}
          {emailSec?.spoofability?.status === 'VULNERABLE' && (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
              <Mail className="w-3.5 h-3.5 mr-1 text-rose-600" />
              DMARC Spoofable
            </span>
          )}
          {webArch?.dormant_revival_detected && (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
              <Flame className="w-3.5 h-3.5 mr-1 text-rose-600" />
              Dormant Revival
            </span>
          )}
          {advDns?.heuristics?.dangling_cnames && advDns.heuristics.dangling_cnames.length > 0 && (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
              <AlertTriangle className="w-3.5 h-3.5 mr-1 text-rose-600" />
              Takeover Candidate
            </span>
          )}
          {cti?.overall_verdict && cti.overall_verdict !== 'clean' && (
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-rose-100 text-rose-800 border border-rose-300">
              <ShieldAlert className="w-3.5 h-3.5 mr-1" />
              CTI: {cti.overall_verdict.toUpperCase()}
            </span>
          )}
          {typeof whois.domain_age_days === 'number' && !isNaN(whois.domain_age_days) && (
            <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${
              whois.domain_age_days < 30
                ? 'bg-amber-100 text-amber-800 border-amber-300 font-semibold'
                : 'bg-emerald-100 text-emerald-800 border-emerald-200'
            }`}>
              <Calendar className="w-3.5 h-3.5 mr-1" />
              {whois.domain_age_formatted || `${whois.domain_age_days} Days Old`}
            </span>
          )}
        </div>
      </div>

      {/* ----------------- EXECUTIVE SECURITY VERDICT BANNER ----------------- */}
      {checklistVerdict && (
        <div className={`p-5 border-b transition-all ${
          checklistVerdict.verdict === 'Malicious'
            ? 'bg-rose-50/90 border-rose-200'
            : checklistVerdict.verdict === 'Suspicious' || checklistVerdict.verdict === 'Vulnerable / Misconfigured'
            ? 'bg-amber-50/90 border-amber-200'
            : checklistVerdict.verdict === 'Private / Internal Indicator'
            ? 'bg-indigo-50/90 border-indigo-200'
            : 'bg-emerald-50/90 border-emerald-200'
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className={`p-2.5 rounded-xl shadow-xs ${
                checklistVerdict.verdict === 'Malicious'
                  ? 'bg-rose-600 text-white'
                  : checklistVerdict.verdict === 'Suspicious' || checklistVerdict.verdict === 'Vulnerable / Misconfigured'
                  ? 'bg-amber-600 text-white'
                  : checklistVerdict.verdict === 'Private / Internal Indicator'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-emerald-600 text-white'
              }`}>
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">
                    Executive Security Verdict
                  </span>
                  <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                    checklistVerdict.severity === 'critical'
                      ? 'bg-rose-200 text-rose-900 border border-rose-300'
                      : checklistVerdict.severity === 'high'
                      ? 'bg-rose-100 text-rose-800 border border-rose-200'
                      : checklistVerdict.severity === 'medium'
                      ? 'bg-amber-100 text-amber-800 border border-amber-200'
                      : checklistVerdict.severity === 'low'
                      ? 'bg-blue-100 text-blue-800 border border-blue-200'
                      : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                  }`}>
                    {checklistVerdict.severity}
                  </span>
                </div>
                <h2 className="text-xl font-black text-slate-900 tracking-tight mt-0.5">
                  {checklistVerdict.verdict}
                </h2>
              </div>
            </div>

            {/* Risk Score & Confidence Gauges with Interactive Hovering Breakdown */}
            <div
              data-domain-risk-card="true"
              className="relative"
              onMouseEnter={() => setIsScoreHovered(true)}
              onMouseLeave={() => setIsScoreHovered(false)}
            >
              <div
                onClick={() => setIsScoreHovered(prev => !prev)}
                className="flex items-center gap-4 bg-white/95 hover:bg-white backdrop-blur-xs p-3 px-4 rounded-xl border border-slate-200/90 hover:border-blue-400 shadow-2xs transition-all cursor-pointer select-none group"
              >
                <div>
                  <div className="flex items-center gap-1 text-[10px] uppercase font-bold text-slate-400 group-hover:text-blue-600 transition-colors">
                    <span>Risk Score</span>
                    <Info className="w-3 h-3 text-blue-500" />
                  </div>
                  <div className="flex items-baseline gap-1">
                    <span className={`text-2xl font-black ${
                      checklistVerdict.risk_score >= 70 ? 'text-rose-600' :
                      checklistVerdict.risk_score >= 40 ? 'text-amber-600' :
                      checklistVerdict.risk_score >= 20 ? 'text-yellow-600' : 'text-emerald-600'
                    }`}>
                      {checklistVerdict.risk_score}
                    </span>
                    <span className="text-xs text-slate-400 font-bold">/100</span>
                  </div>
                </div>
                <div className="h-8 w-px bg-slate-200"></div>
                <div>
                  <div className="text-[10px] uppercase font-bold text-slate-400">Confidence</div>
                  <div className="text-xl font-bold text-slate-700">
                    {checklistVerdict.confidence_score}%
                  </div>
                </div>
              </div>

              {/* Floating Hovering Breakdown Popover */}
              {isScoreHovered && (
                <div className="absolute right-0 top-full mt-2 w-[440px] max-w-[95vw] z-50 p-4 rounded-2xl bg-slate-900 border border-slate-700 text-white shadow-2xl space-y-3 animate-in fade-in duration-150">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs font-bold text-white uppercase tracking-wider">
                        Risk Score Aspect Breakdown
                      </span>
                    </div>
                    <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-emerald-400 border border-slate-700">
                      {checklistVerdict.risk_score}/100 • {checklistVerdict.verdict}
                    </span>
                  </div>

                  {checklistVerdict.risk_breakdown?.summary_explanation && (
                    <p className="text-[11px] text-slate-300 leading-relaxed bg-slate-800/80 p-2.5 rounded-xl border border-slate-700/60">
                      {checklistVerdict.risk_breakdown.summary_explanation}
                    </p>
                  )}

                  {/* 4 Dimension Progress Bars */}
                  {checklistVerdict.risk_breakdown && (
                    <div className="space-y-2.5 text-xs bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                      {/* Threat Intel */}
                      <div>
                        <div className="flex justify-between text-[11px] font-semibold text-slate-300 mb-1">
                          <span>Threat Intelligence (40%)</span>
                          <span className="font-mono text-emerald-400">
                            {checklistVerdict.risk_breakdown.threat_intelligence.score}/100 • {checklistVerdict.risk_breakdown.threat_intelligence.level}
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${checklistVerdict.risk_breakdown.threat_intelligence.score >= 65 ? 'bg-rose-500' : checklistVerdict.risk_breakdown.threat_intelligence.score >= 35 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                            style={{ width: `${Math.max(4, checklistVerdict.risk_breakdown.threat_intelligence.score)}%` }}
                          />
                        </div>
                      </div>

                      {/* Infrastructure */}
                      <div>
                        <div className="flex justify-between text-[11px] font-semibold text-slate-300 mb-1">
                          <span>Infrastructure Reputation (25%)</span>
                          <span className="font-mono text-sky-400">
                            {checklistVerdict.risk_breakdown.infrastructure_reputation.score}/100 • {checklistVerdict.risk_breakdown.infrastructure_reputation.level}
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${checklistVerdict.risk_breakdown.infrastructure_reputation.score >= 50 ? 'bg-rose-500' : checklistVerdict.risk_breakdown.infrastructure_reputation.score >= 25 ? 'bg-amber-500' : 'bg-sky-500'}`}
                            style={{ width: `${Math.max(4, checklistVerdict.risk_breakdown.infrastructure_reputation.score)}%` }}
                          />
                        </div>
                      </div>

                      {/* Cryptographic Trust */}
                      <div>
                        <div className="flex justify-between text-[11px] font-semibold text-slate-300 mb-1">
                          <span>Cryptographic Trust (20%)</span>
                          <span className="font-mono text-purple-400">
                            {checklistVerdict.risk_breakdown.cryptographic_trust.score}/100 • {checklistVerdict.risk_breakdown.cryptographic_trust.level}
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${checklistVerdict.risk_breakdown.cryptographic_trust.score >= 40 ? 'bg-rose-500' : checklistVerdict.risk_breakdown.cryptographic_trust.score >= 20 ? 'bg-amber-500' : 'bg-purple-500'}`}
                            style={{ width: `${Math.max(4, checklistVerdict.risk_breakdown.cryptographic_trust.score)}%` }}
                          />
                        </div>
                      </div>

                      {/* Exposure & Hardening */}
                      <div>
                        <div className="flex justify-between text-[11px] font-semibold text-slate-300 mb-1">
                          <span>Exposure & Hardening (15%)</span>
                          <span className="font-mono text-amber-400">
                            {checklistVerdict.risk_breakdown.exposure_and_hardening.score}/100 • {checklistVerdict.risk_breakdown.exposure_and_hardening.level}
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${checklistVerdict.risk_breakdown.exposure_and_hardening.score >= 40 ? 'bg-rose-500' : checklistVerdict.risk_breakdown.exposure_and_hardening.score >= 20 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                            style={{ width: `${Math.max(4, checklistVerdict.risk_breakdown.exposure_and_hardening.score)}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Factor Details List */}
                  <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      Evaluated Factors & Points:
                    </span>
                    {Object.values(checklistVerdict.risk_breakdown || {})
                      .filter(val => typeof val === 'object' && Array.isArray((val as any).factors))
                      .flatMap((val: any) => val.factors || [])
                      .slice(0, 6)
                      .map((factor: any, fIdx: number) => (
                        <div key={fIdx} className="flex items-start justify-between gap-2 text-[11px] p-2 rounded-lg bg-slate-800/70 border border-slate-700/50">
                          <div className="space-y-0.5">
                            <div className="font-semibold text-slate-200">{factor.name}</div>
                            <div className="text-[10px] text-slate-400 leading-tight">{factor.detail}</div>
                          </div>
                          <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0 ${
                            factor.type === 'penalty' ? 'bg-rose-900/60 text-rose-300 border border-rose-700' :
                            factor.type === 'credit' ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700' :
                            'bg-slate-700 text-slate-300'
                          }`}>
                            {factor.points > 0 ? `+${factor.points} pts` : factor.type === 'credit' ? 'CLEAN' : '0 pts'}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Threat Tags */}
          {checklistVerdict.threat_tags && checklistVerdict.threat_tags.length > 0 && (
            <div className="flex items-center gap-1.5 flex-wrap mt-3 pt-3 border-t border-slate-200/70">
              <span className="text-xs font-semibold text-slate-600 flex items-center gap-1">
                <Tag className="w-3 h-3 text-slate-400" /> Threat Tags:
              </span>
              {checklistVerdict.threat_tags.map((t, idx) => (
                <span key={idx} className="text-xs px-2 py-0.5 bg-white border border-slate-200 rounded-md font-mono text-slate-700 shadow-2xs">
                  {t}
                </span>
              ))}
            </div>
          )}

          {/* MITRE ATT&CK & Rationale Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            {/* Rationale */}
            <div className="bg-white/95 p-3.5 rounded-xl border border-slate-200/80 text-xs shadow-2xs">
              <div className="font-bold text-slate-800 mb-1.5 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-blue-600" />
                Assessment Rationale:
              </div>
              <ul className="space-y-1.5 text-slate-700">
                {checklistVerdict.rationale?.map((r, idx) => (
                  <li key={idx} className="flex items-start gap-1.5 leading-relaxed">
                    <span className="text-blue-500 font-bold mt-0.5">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* MITRE & Containment */}
            <div className="bg-white/95 p-3.5 rounded-xl border border-slate-200/80 text-xs shadow-2xs space-y-2.5">
              {checklistVerdict.mitre_techniques && checklistVerdict.mitre_techniques.length > 0 && (
                <div>
                  <div className="font-bold text-slate-800 mb-1.5 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-indigo-600" />
                    MITRE ATT&CK Mapping:
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {checklistVerdict.mitre_techniques.map((m, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-800 font-mono text-[11px]" title={m.name}>
                        <strong>{m.id}</strong>: {m.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {checklistVerdict.containment_checklist && checklistVerdict.containment_checklist.length > 0 && (
                <div>
                  <div className="font-bold text-slate-800 mb-1.5 flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                    Actionable Containment &amp; Hardening:
                  </div>
                  <ul className="space-y-1 text-slate-700">
                    {checklistVerdict.containment_checklist.slice(0, 3).map((c, idx) => (
                      <li key={idx} className="flex items-start gap-1.5 text-[11px]">
                        <Check className="w-3 h-3 text-emerald-600 mt-0.5 shrink-0" />
                        <span>{c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ----------------- MULTI-DIMENSIONAL RISK GAUGES ----------------- */}
      {scores && (
        <div className="bg-slate-50/70 p-5 border-b border-slate-200">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-600" />
              <span>Multi-Dimensional Threat &amp; Exposure Posture</span>
            </h4>
            <span className="text-[11px] text-slate-500 font-mono">Multi-Axis Risk Engine</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {/* 1. Maliciousness */}
            <div className={`p-3.5 rounded-xl border ${getScoreColor(scores.maliciousness?.level)} flex flex-col justify-between shadow-2xs`}>
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider">Maliciousness</span>
                  <span className="text-lg font-extrabold">{scores.maliciousness?.score ?? 0}<span className="text-xs font-normal">/100</span></span>
                </div>
                <p className="text-[11px] font-medium mt-0.5 capitalize">{scores.maliciousness?.level || 'Clean'} threat indicators</p>
              </div>
              {scores.maliciousness?.factors && scores.maliciousness.factors.length > 0 ? (
                <div className="mt-2.5 pt-2 border-t border-current/20 space-y-1">
                  {scores.maliciousness.factors.slice(0, 2).map((f, i) => (
                    <p key={i} className="text-[10px] truncate" title={f.description}>• {f.title}</p>
                  ))}
                </div>
              ) : null}
            </div>

            {/* 2. Infrastructure Risk */}
            <div className={`p-3.5 rounded-xl border ${getScoreColor(scores.infrastructure_risk?.level)} flex flex-col justify-between shadow-2xs`}>
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider">Infra Risk</span>
                  <span className="text-lg font-extrabold">{scores.infrastructure_risk?.score ?? 0}<span className="text-xs font-normal">/100</span></span>
                </div>
                <p className="text-[11px] font-medium mt-0.5 capitalize">{scores.infrastructure_risk?.level || 'Clean'} hosting setup</p>
              </div>
              {scores.infrastructure_risk?.factors && scores.infrastructure_risk.factors.length > 0 ? (
                <div className="mt-2.5 pt-2 border-t border-current/20 space-y-1">
                  {scores.infrastructure_risk.factors.slice(0, 2).map((f, i) => (
                    <p key={i} className="text-[10px] truncate" title={f.description}>• {f.title}</p>
                  ))}
                </div>
              ) : null}
            </div>

            {/* 3. Exposure */}
            <div className={`p-3.5 rounded-xl border ${getScoreColor(scores.exposure?.level)} flex flex-col justify-between shadow-2xs`}>
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider">Exposure</span>
                  <span className="text-lg font-extrabold">{scores.exposure?.score ?? 0}<span className="text-xs font-normal">/100</span></span>
                </div>
                <p className="text-[11px] font-medium mt-0.5 capitalize">{scores.exposure?.level || 'Clean'} attack surface</p>
              </div>
              {scores.exposure?.factors && scores.exposure.factors.length > 0 ? (
                <div className="mt-2.5 pt-2 border-t border-current/20 space-y-1">
                  {scores.exposure.factors.slice(0, 2).map((f, i) => (
                    <p key={i} className="text-[10px] truncate" title={f.description}>• {f.title}</p>
                  ))}
                </div>
              ) : null}
            </div>

            {/* 4. Attribution Confidence */}
            <div className={`p-3.5 rounded-xl border ${getScoreColor(scores.attribution_confidence?.level)} flex flex-col justify-between shadow-2xs`}>
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider">Attribution</span>
                  <span className="text-lg font-extrabold">{scores.attribution_confidence?.score ?? 0}<span className="text-xs font-normal">/100</span></span>
                </div>
                <p className="text-[11px] font-medium mt-0.5 capitalize">{scores.attribution_confidence?.level || 'Low'} ownership link</p>
              </div>
              {scores.attribution_confidence?.factors && scores.attribution_confidence.factors.length > 0 ? (
                <div className="mt-2.5 pt-2 border-t border-current/20 space-y-1">
                  {scores.attribution_confidence.factors.slice(0, 2).map((f, i) => (
                    <p key={i} className="text-[10px] truncate" title={f.description}>• {f.title}</p>
                  ))}
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* ----------------- TAB NAVIGATION BAR ----------------- */}
      <div className="flex items-center border-b border-slate-200 bg-slate-50/50 px-6 overflow-x-auto gap-1">
        <button
          onClick={() => setActiveTab('overview')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'overview'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Overview</span>
        </button>

        {/* INDICATOR NORMALISATION */}
        <button
          onClick={() => setActiveTab('normalisation')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'normalisation'
              ? 'border-blue-600 text-blue-600 bg-blue-50/40'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-blue-600" />
          <span>Indicator Normalisation</span>
          {normalisation?.ip_classification && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-blue-100 text-blue-800">
              {normalisation.indicator_type.toUpperCase()}
            </span>
          )}
        </button>

        {/* SUBDOMAIN TAKEOVER */}
        {!disabledChecks?.includes('check_subdomains') && (
          <button
            onClick={() => setActiveTab('takeover')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'takeover'
                ? 'border-rose-600 text-rose-600 bg-rose-50/40'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            <span>Subdomain Takeover</span>
            {(() => {
              const count = (takeoverAnalysis?.candidates?.length ?? takeoverAnalysis?.dangling_cnames?.length ?? (takeoverAnalysis?.claimable_count || 0));
              return count > 0 ? (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300 animate-pulse">
                  {count} Vuln
                </span>
              ) : (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-100 text-slate-600">
                  {takeoverAnalysis?.evaluated_count || 0}
                </span>
              );
            })()}
          </button>
        )}

        {/* RELATED INFRASTRUCTURE TAB */}
        <button
          onClick={() => setActiveTab('relations')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'relations'
              ? 'border-indigo-600 text-indigo-600 bg-indigo-50/40'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Network className="w-3.5 h-3.5 text-indigo-600" />
          <span className="font-bold">Related Infrastructure &amp; Pivots</span>
          {directCount > 0 ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-100 text-amber-900 border border-amber-300">
              ★ {directCount} Direct
            </span>
          ) : (
            (relatedDomains.length > 0 || coHosted.length > 0) && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-indigo-100 text-indigo-800">
                {relatedDomains.length}
              </span>
            )
          )}
        </button>

        {/* EMAIL SECURITY */}
        {!disabledChecks?.includes('check_mx_reputation') && (
          <button
            onClick={() => setActiveTab('email_sec')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'email_sec'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Email &amp; DMARC</span>
            {emailSec?.spoofability?.status === 'VULNERABLE' && (
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            )}
          </button>
        )}

        {/* WEB ARCHIVE */}
        <button
          onClick={() => setActiveTab('archive')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'archive'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Archive className="w-3.5 h-3.5" />
          <span>Web Archive</span>
          {webArch?.archived && (
            <span className="text-[10px] bg-blue-50 text-blue-700 border border-blue-200 px-1.5 py-0.2 rounded-full font-mono font-bold">
              {webArch.snapshot_count > 0 ? webArch.snapshot_count : '✓'}
            </span>
          )}
          {webArch?.dormant_revival_detected && (
            <span className="w-2 h-2 rounded-full bg-rose-500" title="Dormant domain revival detected"></span>
          )}
        </button>

        {/* BGP & PASSIVE DNS */}
        <button
          onClick={() => setActiveTab('bgp_pdns')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'bgp_pdns'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Compass className="w-3.5 h-3.5" />
          <span>BGP &amp; pDNS</span>
          {pDns?.total_records ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-200 text-slate-700">
              {pDns.total_records}
            </span>
          ) : null}
        </button>

        {/* ACTIVE RECON */}
        <button
          onClick={() => setActiveTab('recon')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'recon'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Active Security Audit</span>
          {activeProbes?.sensitive_files?.exposed?.length ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rose-100 text-rose-800 font-bold">
              {activeProbes.sensitive_files.exposed.length} leaks
            </span>
          ) : activeRecon?.open_ports_count ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-blue-100 text-blue-800">
              {activeRecon.open_ports_count}
            </span>
          ) : null}
        </button>

        {!disabledChecks?.includes('check_subdomains') && (
          <button
            onClick={() => setActiveTab('surface')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'surface'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Attack Surface ({surface?.total_discovered || 0})</span>
          </button>
        )}

        {!disabledChecks?.includes('check_ssl_tls_cert') && (
          <button
            onClick={() => setActiveTab('tls')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'tls'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>TLS &amp; Certificates</span>
          </button>
        )}

        {!disabledChecks?.includes('check_dns_records') && (
          <button
            onClick={() => setActiveTab('dns')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'dns'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>DNS &amp; DNSSEC</span>
          </button>
        )}

        <button
          onClick={() => setActiveTab('web')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'web'
              ? 'border-blue-600 text-blue-600'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Web Fingerprint</span>
        </button>

        {!disabledChecks?.includes('check_virustotal') && !disabledChecks?.includes('virustotal_enabled') && (
          <button
            onClick={() => setActiveTab('cti')}
            className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'cti'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Threat Feeds (CTI)</span>
          </button>
        )}

        {/* WEB EXPOSURE */}
        <button
          onClick={() => setActiveTab('exposure')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'exposure'
              ? 'border-blue-600 text-blue-600 bg-blue-50/40'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Web Exposure</span>
          {webExposure?.robots_txt?.sensitive_paths_flagged && webExposure.robots_txt.sensitive_paths_flagged.length > 0 ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-amber-100 text-amber-800 font-bold">
              {webExposure.robots_txt.sensitive_paths_flagged.length}
            </span>
          ) : null}
        </button>

        {/* VULNERABILITIES (CISA KEV / EPSS) */}
        <button
          onClick={() => setActiveTab('vulnerabilities')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'vulnerabilities'
              ? 'border-rose-600 text-rose-600 bg-rose-50/40'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Bug className="w-3.5 h-3.5 text-rose-600" />
          <span className="font-bold">Vulnerabilities</span>
          {vulnIntel?.cisa_kev_count ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rose-100 text-rose-800 font-bold">
              {vulnIntel.cisa_kev_count} KEV
            </span>
          ) : vulnIntel?.total_vulnerabilities ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-slate-200 text-slate-700">
              {vulnIntel.total_vulnerabilities}
            </span>
          ) : null}
        </button>

        {/* BRAND DEFENSE & TYPOSQUATTING */}
        <button
          onClick={() => setActiveTab('typosquatting')}
          className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap flex items-center gap-1.5 ${
            activeTab === 'typosquatting'
              ? 'border-amber-600 text-amber-600 bg-amber-50/40'
              : 'border-transparent text-slate-600 hover:text-slate-900'
          }`}
        >
          <Crosshair className="w-3.5 h-3.5 text-amber-600" />
          <span>Brand Defense &amp; Lookalikes</span>
          {typosquat?.active_registered_count ? (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-amber-100 text-amber-800 font-bold">
              {typosquat.active_registered_count} Live
            </span>
          ) : null}
        </button>
      </div>

      {/* ----------------- TAB CONTENTS ----------------- */}
      <div className="p-6">
        {/* ================= TAB: OVERVIEW ================= */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Live Browser Capture */}
            {thumbnailUrl && (
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row items-center gap-4">
                <div className="w-full sm:w-56 h-36 rounded-lg overflow-hidden border border-slate-300 shadow-xs shrink-0 bg-white">
                  <img
                    src={thumbnailUrl}
                    alt={`Live preview for ${domainInfo.target}`}
                    className="w-full h-full object-cover"
                  />
                </div>
                <div className="flex-1 text-left space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                      <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                      Live Sandboxed Browser Snapshot
                    </span>
                    {web?.dom_analysis?.title && (
                      <span className="text-xs text-slate-600 font-medium truncate max-w-sm">
                        &quot;{web.dom_analysis.title}&quot;
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Browser executed rendering inside FileSanitizer&apos;s isolated sandbox container. Target responded with HTTP status <span className="font-mono font-bold text-slate-800">{web?.status_code || 200}</span>.
                  </p>
                  <div className="flex items-center gap-3 pt-1 text-xs font-mono text-slate-500">
                    <span>Hops: {web?.hop_count || 0}</span>
                    <span>• Security Grade: <strong className="text-slate-800">{web?.security_headers?.grade || 'N/A'}</strong></span>
                    {web?.favicon?.murmur_hash && (
                      <span>• Favicon Hash: <strong className="text-blue-700">{web.favicon.murmur_hash}</strong></span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Key Infrastructure Attributes Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {!disabledChecks?.includes('check_whois_rdap') && (
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Registration &amp; Registrar</span>
                  <p className="text-sm font-semibold text-slate-800">{whois.registrar || 'Unknown Registrar'}</p>
                  <p className="text-xs text-slate-500 font-mono">
                    Created: {whois.registration_date ? new Date(whois.registration_date).toLocaleDateString() : 'Unknown'}
                  </p>
                </div>
              )}

              <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Autonomous System &amp; Host</span>
                <p className="text-sm font-semibold text-slate-800">{asnProf?.as_org || net?.as_org || 'Unknown ASN'}</p>
                <p className="text-xs text-slate-500 font-mono">
                  {asnProf?.asn || net?.asn || 'AS---'} • {asnProf?.country || net?.country || 'Global'}
                </p>
              </div>

              {(!disabledChecks?.includes('check_dns_records') || !disabledChecks?.includes('check_mx_reputation')) && (
                <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Security Controls Posture</span>
                  <p className="text-sm font-semibold text-slate-800 flex items-center gap-2">
                    {!disabledChecks?.includes('check_dns_records') && (
                      <span>DNSSEC: {advDns?.dnssec?.enabled ? 'Signed' : 'Unsigned'}</span>
                    )}
                    {!disabledChecks?.includes('check_dns_records') && <span>•</span>}
                    <span>Headers: {web?.security_headers?.grade || 'F'}</span>
                  </p>
                  {!disabledChecks?.includes('check_mx_reputation') && (
                    <p className="text-xs text-slate-500 font-mono">
                      Email DMARC: {emailSec?.dmarc?.policy ? `p=${emailSec.dmarc.policy}` : 'None'}
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Forward-Confirmed Reverse DNS (FCrDNS) Verification Card */}
            {fcrdns && (
              <div className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
                fcrdns.status === 'VALID'
                  ? 'bg-emerald-50/60 border-emerald-200 text-emerald-950'
                  : fcrdns.status === 'MISMATCH'
                  ? 'bg-rose-50/70 border-rose-300 text-rose-950'
                  : 'bg-slate-50 border-slate-200 text-slate-800'
              }`}>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold uppercase tracking-wider flex items-center gap-1.5">
                      {fcrdns.status === 'VALID' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                      ) : fcrdns.status === 'MISMATCH' ? (
                        <AlertCircle className="w-4 h-4 text-rose-600" />
                      ) : (
                        <Info className="w-4 h-4 text-slate-500" />
                      )}
                      <span>Forward-Confirmed Reverse DNS (FCrDNS)</span>
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      fcrdns.status === 'VALID'
                        ? 'bg-emerald-200 text-emerald-900'
                        : fcrdns.status === 'MISMATCH'
                        ? 'bg-rose-200 text-rose-900'
                        : 'bg-slate-200 text-slate-700'
                    }`}>
                      {fcrdns.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-700 font-mono">
                    IP: <strong>{fcrdns.ip || net.ip || 'Unknown'}</strong> {fcrdns.primary_ptr ? `⇄ PTR: ${fcrdns.primary_ptr}` : '⇄ No PTR record configured'}
                  </p>
                  <p className="text-[11px] text-slate-600 leading-relaxed">
                    {fcrdns.details || (fcrdns.status === 'VALID' ? 'Bidirectional PTR to forward IP resolution verified. Anti-spoofing and MTA trust confirmed.' : 'Reverse hostname does not forward-resolve back to source IP.')}
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('dns')}
                  className="px-3 py-1.5 bg-white border border-slate-300 hover:bg-slate-50 rounded-lg text-xs font-medium text-slate-700 shrink-0 shadow-2xs cursor-pointer flex items-center gap-1"
                >
                  <span>View DNS Details</span>
                  <ArrowRight className="w-3 h-3 text-slate-400" />
                </button>
              </div>
            )}

            {/* Quick Intelligence Summary Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {/* Vulnerabilities Summary Card */}
              <div
                onClick={() => setActiveTab('vulnerabilities')}
                className="p-3.5 bg-slate-50 hover:bg-rose-50/40 border border-slate-200 hover:border-rose-300 rounded-xl transition-all cursor-pointer space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                    <Bug className="w-3 h-3 text-rose-600" />
                    <span>Vulnerabilities</span>
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    vulnIntel?.cisa_kev_count ? 'bg-rose-100 text-rose-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {vulnIntel?.cisa_kev_count ? `${vulnIntel.cisa_kev_count} KEV` : `${vulnIntel?.total_vulnerabilities || 0} CVEs`}
                  </span>
                </div>
                <p className="text-xs text-slate-700 font-medium">
                  {vulnIntel?.has_critical_kev ? 'Weaponized Exploits Found' : vulnIntel?.total_vulnerabilities ? 'Component Versions Evaluated' : 'No Cataloged Exploits'}
                </p>
                <p className="text-[10px] text-slate-400 font-mono">Max EPSS: {vulnIntel?.max_epss_score ? `${(vulnIntel.max_epss_score * 100).toFixed(1)}%` : '0%'}</p>
              </div>

              {/* Web Exposure Summary Card */}
              <div
                onClick={() => setActiveTab('exposure')}
                className="p-3.5 bg-slate-50 hover:bg-blue-50/40 border border-slate-200 hover:border-blue-300 rounded-xl transition-all cursor-pointer space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                    <FileText className="w-3 h-3 text-blue-600" />
                    <span>Web Exposure</span>
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-800 font-mono">
                    {webExposure?.robots_txt?.sensitive_paths_flagged?.length || 0} Flags
                  </span>
                </div>
                <p className="text-xs text-slate-700 font-medium">
                  {webExposure?.robots_txt?.present ? 'Robots.txt & Sitemaps Parsed' : 'No robots.txt detected'}
                </p>
                <p className="text-[10px] text-slate-400 font-mono">Security.txt: {webExposure?.well_known?.security_txt?.present ? 'Configured' : 'Missing'}</p>
              </div>

              {/* Typosquatting Summary Card */}
              <div
                onClick={() => setActiveTab('typosquatting')}
                className="p-3.5 bg-slate-50 hover:bg-amber-50/40 border border-slate-200 hover:border-amber-300 rounded-xl transition-all cursor-pointer space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                    <Crosshair className="w-3 h-3 text-amber-600" />
                    <span>Brand Defense</span>
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    typosquat?.active_registered_count ? 'bg-amber-100 text-amber-800' : 'bg-slate-200 text-slate-700'
                  }`}>
                    {typosquat?.active_registered_count || 0} Live Lookalikes
                  </span>
                </div>
                <p className="text-xs text-slate-700 font-medium">
                  {typosquat?.has_live_impersonators ? 'Active Impersonators Resolving' : 'Permutations Generated'}
                </p>
                <p className="text-[10px] text-slate-400 font-mono">{typosquat?.total_generated || 0} Variants Checked</p>
              </div>

              {/* Snapshot Comparison Summary Card */}
              <div
                onClick={() => setActiveTab('archive')}
                className="p-3.5 bg-slate-50 hover:bg-indigo-50/40 border border-slate-200 hover:border-indigo-300 rounded-xl transition-all cursor-pointer space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1">
                    <GitCompare className="w-3 h-3 text-indigo-600" />
                    <span>Time Delta</span>
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-100 text-indigo-800 font-mono">
                    {snapshotDiff?.total_changes_detected || 0} Shifts
                  </span>
                </div>
                <p className="text-xs text-slate-700 font-medium truncate">
                  {snapshotDiff?.has_historical_baseline ? `Baseline: Job ${snapshotDiff.baseline_job_id?.slice(0, 8)}` : 'Baseline Established'}
                </p>
                <p className="text-[10px] text-slate-400 font-mono">{snapshotDiff?.has_historical_baseline ? 'Deltas Tracked' : 'Subsequent scans diffed'}</p>
              </div>
            </div>

            {/* Risk Flags & Anomalies */}
            {domainInfo.risk_flags && domainInfo.risk_flags.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                  Identified Security Risks &amp; Anomalies ({domainInfo.risk_flags.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {domainInfo.risk_flags.map((rf, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-xl border flex items-start gap-2.5 ${
                        rf.severity === 'critical'
                          ? 'bg-rose-50 border-rose-200 text-rose-900'
                          : rf.severity === 'high'
                          ? 'bg-amber-50 border-amber-200 text-amber-900'
                          : 'bg-blue-50 border-blue-200 text-blue-900'
                      }`}
                    >
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-current" />
                      <div>
                        <p className="text-xs font-bold">{rf.title}</p>
                        <p className="text-[11px] text-current/80 mt-0.5 leading-relaxed">{rf.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: RESTORED & EVOLVED RELATED INFRASTRUCTURE ================= */}
        {activeTab === 'relations' && (
          <div className="space-y-5">
            {/* Pivots Execution & ASN Summary Banner */}
            <div className="p-4 bg-gradient-to-r from-indigo-50/70 via-slate-50 to-white border border-indigo-100 rounded-xl space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <Network className="w-4 h-4 text-indigo-600" />
                    <span>Correlated Infrastructure &amp; Ownership Pivots</span>
                  </h4>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Discovers sibling assets sharing dedicated autonomous systems, CIDR netblocks, reverse PTR sweeps, TLS certificates, and passive DNS co-location.
                  </p>
                </div>
                {ownershipPivots?.is_shared_infrastructure ? (
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-900 border border-amber-300">
                    Shared Cloud / DDoS Scrubbing Edge
                  </span>
                ) : (
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
                    Dedicated / Corporate Network
                  </span>
                )}
              </div>

              {/* Pivot Facts Pills & Direct Affiliates Count */}
              <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                {ownershipPivots?.asn && (
                  <span className="px-2.5 py-1 bg-white border border-slate-200 rounded-md font-mono text-slate-800 shadow-2xs">
                    ASN: <strong>{ownershipPivots.asn}</strong> {ownershipPivots.asn_holder ? `(${ownershipPivots.asn_holder})` : ''}
                  </span>
                )}
                {ownershipPivots?.owner_org && (
                  <span className="px-2.5 py-1 bg-white border border-slate-200 rounded-md text-slate-800 shadow-2xs">
                    Org: <strong>{ownershipPivots.owner_org}</strong>
                  </span>
                )}
                <span className="px-2.5 py-1 bg-amber-50 border border-amber-200 rounded-md text-amber-900 font-semibold shadow-2xs flex items-center gap-1">
                  <Star className="w-3 h-3 text-amber-600 fill-amber-500" />
                  <span>Direct Corporate Affiliates: <strong>{directCount}</strong></span>
                </span>
                <span className="px-2.5 py-1 bg-slate-100 border border-slate-200 rounded-md text-slate-700 shadow-2xs">
                  Multi-Tenant Neighbors: <strong>{sharedCount}</strong>
                </span>
                {ownershipPivots?.elapsed_s ? (
                  <span className="px-2.5 py-1 bg-white border border-slate-200 rounded-md text-slate-500 font-mono shadow-2xs">
                    Duration: {ownershipPivots.elapsed_s}s
                  </span>
                ) : null}
              </div>

              {ownershipPivots?.shared_reason && (
                <div className="text-[11px] text-amber-900 bg-amber-50/90 p-2.5 rounded-lg border border-amber-200 flex items-start gap-2">
                  <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-700" />
                  <p>{ownershipPivots.shared_reason}</p>
                </div>
              )}
            </div>

            {/* View Selector Tabs and Search/Filter Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
              <div className="flex items-center gap-2 flex-wrap">
                {/* View Mode Pills */}
                <div className="inline-flex rounded-lg border border-slate-200 p-0.5 bg-slate-100 text-xs">
                  <button
                    onClick={() => setRelationViewTab('direct')}
                    className={`px-3 py-1 rounded-md font-semibold transition-all flex items-center gap-1 ${
                      relationViewTab === 'direct'
                        ? 'bg-white text-indigo-700 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Star className="w-3 h-3 text-amber-500 fill-amber-500" />
                    <span>Direct Affiliates ({directCount})</span>
                  </button>
                  <button
                    onClick={() => setRelationViewTab('shared')}
                    className={`px-3 py-1 rounded-md font-semibold transition-all flex items-center gap-1 ${
                      relationViewTab === 'shared'
                        ? 'bg-white text-amber-800 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Layers className="w-3 h-3 text-amber-600" />
                    <span>Multi-Tenant Neighbors ({sharedCount})</span>
                  </button>
                  <button
                    onClick={() => setRelationViewTab('all')}
                    className={`px-3 py-1 rounded-md font-semibold transition-all ${
                      relationViewTab === 'all'
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    All ({relatedDomains.length})
                  </button>
                </div>

                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={relationSearch}
                    onChange={e => setRelationSearch(e.target.value)}
                    placeholder="Search discovered domains..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-hidden focus:ring-1 focus:ring-indigo-500 font-mono w-52"
                  />
                </div>

                {/* Relationship Type Filters */}
                <select
                  value={relationFilter}
                  onChange={e => setRelationFilter(e.target.value)}
                  className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 font-medium focus:outline-hidden"
                >
                  <option value="all">All Relationships</option>
                  <option value="shared_certificate">Shared TLS Certificate (SAN)</option>
                  <option value="cert_organization">Cert Org Link</option>
                  <option value="shared_tracking_id">Shared Web Analytics / Tag Manager</option>
                  <option value="spf_reference">SPF Reference</option>
                  <option value="same_network">Same Corporate Subnet (/24)</option>
                  <option value="same_ip">Same IP Address</option>
                  <option value="shared_nameserver">Shared Nameserver</option>
                </select>

                {/* Confidence Filter */}
                <select
                  value={confidenceFilter}
                  onChange={e => setConfidenceFilter(e.target.value)}
                  className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 font-medium focus:outline-hidden"
                >
                  <option value="all">All Confidence</option>
                  <option value="high">High Confidence Only</option>
                  <option value="medium">Medium &amp; High</option>
                  <option value="low">Low Confidence</option>
                </select>
              </div>

              <span className="text-xs text-slate-500 font-mono self-center">
                {relationViewTab === 'direct' ? `Showing ${filteredDirectAffiliates.length} of ${directCount} direct affiliates` :
                 relationViewTab === 'shared' ? `Showing ${filteredSharedNeighbors.length} of ${sharedCount} multi-tenant neighbors` :
                 `Showing ${filteredRelations.length} of ${relatedDomains.length} total domains`}
              </span>
            </div>

            {/* ================= SECTION 1: DIRECT CORPORATE AFFILIATES & VERIFIED SIBLINGS ================= */}
            {(relationViewTab === 'direct' || relationViewTab === 'all') && (
              <div className="p-4 bg-white border border-indigo-200 rounded-xl space-y-3 shadow-2xs">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 bg-amber-50 rounded-lg text-amber-600 border border-amber-200">
                      <Star className="w-4 h-4 fill-amber-500" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                        <span>Verified Direct Affiliates &amp; Corporate Siblings</span>
                        <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 font-mono">
                          {filteredDirectAffiliates.length}
                        </span>
                      </h4>
                      <p className="text-xs text-slate-600 mt-0.5">
                        High-confidence organizational connections verified through cryptographic TLS SAN certificates, corporate WHOIS organization matching, shared private tracking containers, or authorized SPF delegations.
                      </p>
                    </div>
                  </div>
                </div>

                {filteredDirectAffiliates.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    {filteredDirectAffiliates.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 bg-indigo-50/30 border border-indigo-200/80 hover:border-indigo-400 rounded-xl flex flex-col justify-between gap-2.5 transition-colors shadow-2xs"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-xs font-bold text-slate-900 truncate" title={item.domain}>
                              {item.domain}
                            </span>
                            <div className="flex items-center gap-1.5 shrink-0">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-900 border border-amber-200 flex items-center gap-1">
                                <Star className="w-2.5 h-2.5 fill-amber-500 text-amber-600" />
                                <span>Direct Affiliate</span>
                              </span>
                              <InvestigateAssetButton
                                ioc={item.domain}
                                iocType="domain"
                                compact={true}
                                onNavigateToJob={onNavigateToJob}
                              />
                            </div>
                          </div>

                          {/* Relationship Labels */}
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            {(item.relationship_labels || item.relationships || []).map((label: string, lidx: number) => (
                              <span
                                key={lidx}
                                className="px-2 py-0.5 bg-indigo-100 border border-indigo-300 text-indigo-900 text-[10px] rounded-md font-semibold"
                              >
                                {label}
                              </span>
                            ))}
                          </div>

                          {/* Evidence Snippet */}
                          {item.evidence && item.evidence.length > 0 && (
                            <div className="mt-2 space-y-1 font-mono text-[11px] text-slate-700 bg-white p-2 rounded-lg border border-slate-200/80">
                              {item.evidence.map((ev: string, eidx: number) => (
                                <p key={eidx} className="truncate" title={ev}>• {ev}</p>
                              ))}
                            </div>
                          )}
                        </div>

                        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1 border-t border-indigo-100">
                          <span>Evidence: {(item.sources || []).join(', ') || 'Cryptographic / CT'}</span>
                          {item.ips && item.ips.length > 0 && (
                            <span className="truncate max-w-[160px]" title={item.ips.join(', ')}>IP: {item.ips[0]}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-6 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500 bg-slate-50/50">
                    <ShieldCheck className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                    <p className="font-semibold text-slate-700">No direct cryptographic or tracking affiliates match this filter.</p>
                    <p className="text-slate-400 mt-0.5">Check the multi-tenant infrastructure accordion below for co-hosted cloud neighbors.</p>
                  </div>
                )}
              </div>
            )}

            {/* ================= SECTION 2: COLLAPSIBLE MULTI-TENANT & CO-HOSTED NEIGHBORS ================= */}
            {(relationViewTab === 'direct' || relationViewTab === 'shared' || relationViewTab === 'all') && (
              <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
                <button
                  onClick={() => setShowSharedAccordion(!showSharedAccordion)}
                  className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-amber-50 rounded-lg text-amber-700 border border-amber-200">
                      <Layers className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-xs font-bold text-slate-900">
                          Multi-Tenant Infrastructure &amp; Co-Hosted Neighbors
                        </h4>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-100 text-slate-700 border border-slate-200 font-mono">
                          {filteredSharedNeighbors.length} Domains
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-50 text-amber-800 border border-amber-200">
                          {showSharedAccordion ? 'Expanded' : 'Collapsed to Reduce Noise'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Co-hosted on shared cloud/CDN/DDoS edge IPs (e.g. Baffin Bay Networks / Microsoft) or public registrar nameservers.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-xs font-semibold text-slate-600 shrink-0">
                    <span>{showSharedAccordion ? 'Hide Neighbors' : `Inspect ${filteredSharedNeighbors.length} Neighbors`}</span>
                    {showSharedAccordion ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                  </div>
                </button>

                {(showSharedAccordion || relationViewTab === 'shared') && (
                  <div className="p-4 border-t border-slate-100 bg-slate-50/50 space-y-3">
                    <div className="p-2.5 bg-amber-50/80 border border-amber-200 rounded-lg text-[11px] text-amber-900 flex items-start gap-2">
                      <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-amber-700" />
                      <p>
                        These domains share multi-tenant edge addresses or registrar nameservers with the target. Because the infrastructure provider (e.g. DDoS scrubber or cloud host) serves multiple independent organizations, these neighbors are kept separate to prevent false attribution.
                      </p>
                    </div>

                    {filteredSharedNeighbors.length > 0 ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto pr-1">
                        {filteredSharedNeighbors.map((item, idx) => (
                          <div
                            key={idx}
                            className="p-3 bg-white border border-slate-200 hover:border-slate-300 rounded-xl flex flex-col justify-between gap-2 shadow-2xs"
                          >
                            <div>
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-mono text-xs font-bold text-slate-900 truncate" title={item.domain}>
                                  {item.domain}
                                </span>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  <span className={`px-2 py-0.5 rounded-full text-[10px] uppercase tracking-wider border ${getConfidenceBadge(item.confidence)}`}>
                                    {item.confidence}
                                  </span>
                                  <InvestigateAssetButton
                                    ioc={item.domain}
                                    iocType="domain"
                                    compact={true}
                                    onNavigateToJob={onNavigateToJob}
                                  />
                                </div>
                              </div>
                              <div className="flex flex-wrap gap-1 mt-1.5">
                                {(item.relationship_labels || item.relationships || []).map((label: string, lidx: number) => (
                                  <span
                                    key={lidx}
                                    className="px-1.5 py-0.5 bg-slate-100 border border-slate-200 text-slate-700 text-[10px] rounded font-medium"
                                  >
                                    {label}
                                  </span>
                                ))}
                              </div>
                              {item.evidence && item.evidence.length > 0 && (
                                <p className="mt-1.5 text-[11px] font-mono text-slate-500 truncate" title={item.evidence[0]}>
                                  • {item.evidence[0]}
                                </p>
                              )}
                            </div>
                            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-100">
                              <span>Source: {(item.sources || []).join(', ') || 'PTR/IP'}</span>
                              {item.ips && item.ips.length > 0 && <span className="truncate max-w-[140px]">IP: {item.ips[0]}</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-6 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                        No multi-tenant infrastructure neighbors match your current filters.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Reverse Nameserver (Reverse-NS) Infrastructure */}
            {revInfra?.reverse_ns && revInfra.reverse_ns.length > 0 && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Server className="w-4 h-4 text-indigo-600" />
                      <span>Reverse Nameserver (Reverse-NS) Infrastructure</span>
                    </h4>
                    <p className="text-xs text-slate-600 mt-0.5">
                      Identifies sibling domains sharing authoritative nameservers, distinguishing dedicated private DNS from multi-tenant cloud providers.
                    </p>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-100 text-indigo-800 border border-indigo-200">
                    {revInfra.reverse_ns.length} Nameservers
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  {revInfra.reverse_ns.map((nsItem, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-lg border border-slate-200 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900 truncate" title={nsItem.nameserver}>
                          {nsItem.nameserver}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          nsItem.is_shared_provider
                            ? 'bg-amber-50 text-amber-800 border-amber-200'
                            : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        }`}>
                          {nsItem.is_shared_provider ? 'Shared Provider' : 'Dedicated / Private'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-600 flex items-center justify-between">
                        <span>Confidence: <strong className="text-slate-800">{nsItem.attribution_confidence}</strong></span>
                        <span>Associated: <strong className="text-indigo-700">{nsItem.count} domains</strong></span>
                      </div>
                      {nsItem.associated_domains && nsItem.associated_domains.length > 0 && (
                        <div className="pt-1.5 border-t border-slate-100 flex flex-wrap gap-1.5 items-center">
                          {nsItem.associated_domains.slice(0, 4).map((dom, dIdx) => (
                            <div key={dIdx} className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded border border-slate-200 text-[11px] font-mono">
                              <span className="text-slate-700">{dom}</span>
                              <InvestigateAssetButton ioc={dom} iocType="domain" compact={true} onNavigateToJob={onNavigateToJob} />
                            </div>
                          ))}
                          {nsItem.associated_domains.length > 4 && (
                            <span className="text-[10px] text-slate-400 font-mono">
                              +{nsItem.associated_domains.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Reverse Mail Server (Reverse-MX) Infrastructure */}
            {revInfra?.reverse_mx && revInfra.reverse_mx.length > 0 && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Mail className="w-4 h-4 text-blue-600" />
                      <span>Reverse Mail Server (Reverse-MX) Infrastructure</span>
                    </h4>
                    <p className="text-xs text-slate-600 mt-0.5">
                      Discovers domains sharing mail exchange servers, isolating enterprise mail clusters from public hosted email.
                    </p>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200">
                    {revInfra.reverse_mx.length} MX Hosts
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  {revInfra.reverse_mx.map((mxItem, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-lg border border-slate-200 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-bold text-slate-900 truncate" title={mxItem.mx_host}>
                          {mxItem.mx_host}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          mxItem.is_shared_provider
                            ? 'bg-blue-50 text-blue-800 border-blue-200'
                            : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                        }`}>
                          {mxItem.is_shared_provider ? 'Shared Provider' : 'Dedicated / Private'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-600 flex items-center justify-between">
                        <span>Confidence: <strong className="text-slate-800">{mxItem.attribution_confidence}</strong></span>
                        <span>Associated: <strong className="text-blue-700">{mxItem.count} domains</strong></span>
                      </div>
                      {mxItem.associated_domains && mxItem.associated_domains.length > 0 && (
                        <div className="pt-1.5 border-t border-slate-100 flex flex-wrap gap-1.5 items-center">
                          {mxItem.associated_domains.slice(0, 4).map((dom, dIdx) => (
                            <div key={dIdx} className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded border border-slate-200 text-[11px] font-mono">
                              <span className="text-slate-700">{dom}</span>
                              <InvestigateAssetButton ioc={dom} iocType="domain" compact={true} onNavigateToJob={onNavigateToJob} />
                            </div>
                          ))}
                          {mxItem.associated_domains.length > 4 && (
                            <span className="text-[10px] text-slate-400 font-mono">
                              +{mxItem.associated_domains.length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Reverse Tracking & Analytics Identifier Pivots */}
            {trackingPivots && trackingPivots.tracking_identifiers && trackingPivots.tracking_identifiers.length > 0 && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                      <Tag className="w-4 h-4 text-purple-600" />
                      <span>Reverse Tracking &amp; Analytics Identifier Pivots</span>
                    </h4>
                    <p className="text-xs text-slate-600 mt-0.5">
                      Correlates web properties via shared Google Analytics (UA / G-), Google Tag Manager (GTM-), AdSense (pub-), and Microsoft Clarity IDs embedded in client-side code.
                    </p>
                  </div>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-100 text-purple-800 border border-purple-200">
                    {trackingPivots.total_identifiers} Identifiers
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  {trackingPivots.tracking_identifiers.map((item, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-lg border border-slate-200 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-100 text-purple-800">
                            {item.type}
                          </span>
                          <span className="font-mono text-xs font-bold text-slate-900">{item.identifier}</span>
                        </div>
                        {item.query_url && (
                          <a
                            href={item.query_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-purple-600 hover:text-purple-800 inline-flex items-center gap-1 text-[11px] font-medium"
                          >
                            <span>NerdyData / Search</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-600 flex items-center justify-between">
                        <span>Confidence: <strong className="text-slate-800">{item.attribution_confidence}</strong></span>
                        <span>Associated Domains: <strong className="text-purple-700">{item.count}</strong></span>
                      </div>
                      {item.associated_domains && item.associated_domains.length > 0 && (
                        <div className="pt-1.5 border-t border-slate-100 flex flex-wrap gap-1.5 items-center">
                          {item.associated_domains.map((dom, dIdx) => (
                            <div key={dIdx} className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded border border-slate-200 text-[11px] font-mono">
                              <span className="text-slate-700">{dom}</span>
                              <InvestigateAssetButton ioc={dom} iocType="domain" compact={true} onNavigateToJob={onNavigateToJob} />
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: EMAIL SECURITY & DMARC ================= */}
        {activeTab === 'email_sec' && (
          <div className="space-y-6">
            {emailSec ? (
              <>
                {/* Spoofability Risk Assessment Card */}
                <div className={`p-4 rounded-xl border ${
                  emailSec.spoofability.status === 'SECURED'
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
                    : emailSec.spoofability.status === 'PARTIALLY_PROTECTED'
                    ? 'bg-amber-50 border-amber-200 text-amber-950'
                    : 'bg-rose-50 border-rose-200 text-rose-950'
                } flex flex-col md:flex-row items-start md:items-center justify-between gap-4`}>
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="w-5 h-5 shrink-0" />
                      <h4 className="text-sm font-bold">
                        Email Spoofability Status: {emailSec.spoofability.status.replace('_', ' ')}
                      </h4>
                    </div>
                    <p className="text-xs leading-relaxed opacity-90">
                      {emailSec.spoofability.summary}
                    </p>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="text-2xl font-extrabold">{emailSec.spoofability.risk_score}</span>
                    <span className="text-xs font-normal"> /100 Risk</span>
                  </div>
                </div>

                {/* Remediation Checklist */}
                {emailSec.spoofability.remediations && emailSec.spoofability.remediations.length > 0 && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Recommended Hardening Actions</h5>
                    <ul className="space-y-1 text-xs text-slate-600">
                      {emailSec.spoofability.remediations.map((rec, i) => (
                        <li key={i} className="flex items-center gap-2">
                          <ArrowRight className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Email Domain Posture & SPF Limits Audit */}
                {emailPosture && (
                  <div className="p-4 bg-blue-50/50 border border-blue-200 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <h5 className="text-xs font-bold text-blue-900 uppercase tracking-wider flex items-center gap-1.5">
                        <Mail className="w-4 h-4 text-blue-600" />
                        <span>Email Infrastructure Posture &amp; SPF Limits Audit</span>
                      </h5>
                      <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-blue-100 text-blue-800 border border-blue-300">
                        {emailPosture.overall_posture || (emailPosture.is_spoofable ? 'Vulnerable / Spoofable' : 'Hardened / Enforced')}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                      <div className="p-3 bg-white rounded-lg border border-blue-100">
                        <span className="text-[10px] uppercase font-bold text-slate-400">SPF Lookups Count</span>
                        <p className={`text-base font-bold mt-0.5 ${emailPosture.spf?.lookup_limit_exceeded ? 'text-rose-600' : 'text-slate-800'}`}>
                          {emailPosture.spf?.lookup_count || 0} / 10 limit
                        </p>
                        <p className="text-[10px] text-slate-500">Qualifier: {emailPosture.spf?.qualifier || emailPosture.spf?.all_qualifier || '(none)'} ({emailPosture.spf?.qualifier_safety || 'Standard'})</p>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-blue-100">
                        <span className="text-[10px] uppercase font-bold text-slate-400">DMARC Enforcement</span>
                        <p className={`text-base font-bold mt-0.5 ${emailPosture.dmarc?.is_enforced ? 'text-emerald-600' : 'text-amber-600'}`}>
                          {emailPosture.dmarc?.is_enforced ? 'Enforced (' + emailPosture.dmarc?.policy + ')' : 'Audit Only (' + (emailPosture.dmarc?.policy || 'none') + ')'}
                        </p>
                        <p className="text-[10px] text-slate-500">Subdomains: {emailPosture.dmarc?.subdomain_policy || 'inherit'}</p>
                      </div>

                      <div className="p-3 bg-white rounded-lg border border-blue-100">
                        <span className="text-[10px] uppercase font-bold text-slate-400">MTA-STS &amp; TLS-RPT</span>
                        <p className="text-base font-bold text-slate-800 mt-0.5">
                          {(emailPosture.mta_sts?.enabled || emailPosture.mta_sts?.published) ? 'MTA-STS Enabled' : 'No MTA-STS'}
                        </p>
                        <p className="text-[10px] text-slate-500">TLS-RPT: {(emailPosture.tls_rpt?.enabled || emailPosture.tls_rpt?.published) ? 'Configured' : 'Missing'}</p>
                      </div>
                    </div>
                  </div>
                )}

                {/* DMARC, DKIM, BIMI Specs Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* DMARC Dissection */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Mail className="w-3.5 h-3.5 text-blue-600" />
                      <span>DMARC Policy</span>
                    </h5>
                    <div className="space-y-1.5 text-xs font-mono">
                      <p>Policy: <strong className="uppercase text-slate-800">{emailSec.dmarc.policy}</strong></p>
                      <p>Subdomain: <span className="text-slate-600">{emailSec.dmarc.subdomain_policy || 'inherit'}</span></p>
                      <p>Enforcement: <span className={emailSec.dmarc.is_enforced ? 'text-emerald-700 font-bold' : 'text-rose-600 font-bold'}>
                        {emailSec.dmarc.is_enforced ? 'Active' : 'Unenforced'}
                      </span></p>
                      <p>Percentage: <span className="text-slate-600">{emailSec.dmarc.percentage}%</span></p>
                    </div>
                    {emailSec.dmarc.raw_record && (
                      <div className="pt-2 border-t border-slate-200">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] text-slate-400">Raw Record:</span>
                          <button
                            onClick={() => copyToClipboard(emailSec.dmarc.raw_record || '', 'dmarc')}
                            className="text-[10px] text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
                          >
                            {copiedKey === 'dmarc' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === 'dmarc' ? 'Copied' : 'Copy'}</span>
                          </button>
                        </div>
                        <div className="p-2 bg-white rounded border border-slate-200 text-[10px] font-mono text-slate-700 break-all select-all">
                          {emailSec.dmarc.raw_record}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* DKIM Selectors Probed */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-blue-600" />
                      <span>DKIM Keys Probed</span>
                    </h5>
                    <p className="text-xs text-slate-600">
                      Checked {emailSec.dkim.selectors_checked} common selector prefixes. Found {emailSec.dkim.selectors_found.length} active key(s).
                    </p>
                    {emailSec.dkim.selectors_found.length > 0 ? (
                      <div className="space-y-1.5 pt-1">
                        {emailSec.dkim.selectors_found.map((sel, idx) => (
                          <div key={idx} className="p-2 bg-white rounded border border-slate-200 text-xs font-mono">
                            <span className="font-bold text-slate-800">{sel.selector}._domainkey</span>
                            {sel.key_size_bits && (
                              <span className="ml-2 text-[10px] px-1.5 py-0.2 bg-emerald-100 text-emerald-800 rounded">
                                ~{sel.key_size_bits}-bit RSA
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs font-mono text-slate-400">No standard DKIM selectors matched.</p>
                    )}
                  </div>

                  {/* BIMI Brand Validation */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <CheckCircle className="w-3.5 h-3.5 text-blue-600" />
                      <span>BIMI Brand Indicator</span>
                    </h5>
                    <div className="space-y-1.5 text-xs">
                      <p>Published: <strong className="text-slate-800">{emailSec.bimi.present ? 'Yes' : 'No'}</strong></p>
                      <p>VMC Certificate: <span className="text-slate-600">{emailSec.bimi.has_vmc ? 'Verified' : 'None'}</span></p>
                      {emailSec.bimi.svg_logo_url && (
                        <p className="truncate text-[11px] text-blue-600">
                          <a href={emailSec.bimi.svg_logo_url} target="_blank" rel="noopener noreferrer" className="hover:underline">
                            View Brand SVG Logo
                          </a>
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                Email security audit is only applicable to domain targets.
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: HISTORICAL WEB ARCHIVE ================= */}
        {activeTab === 'archive' && (() => {
          const cleanTarget = (domainInfo.target || '').replace(/^https?:\/\//i, '').replace(/\/+$/, '');
          const waybackHttpUrl = webArch?.wayback_calendar_url || `https://web.archive.org/web/*/http://${cleanTarget}*`;
          const waybackHttpsUrl = webArch?.wayback_https_calendar_url || `https://web.archive.org/web/*/https://${cleanTarget}*`;
          const waybackWwwUrl = webArch?.wayback_www_calendar_url || `https://web.archive.org/web/*/http://www.${cleanTarget.replace(/^www\./i, '')}*`;
          const archiveTodayUrl = `https://archive.today/newest/https://${cleanTarget}`;
          const urlscanUrl = `https://urlscan.io/search/#page.domain%3A${encodeURIComponent(cleanTarget)}`;

          return (
            <div className="space-y-5">
              {webArch ? (
                <>
                  {/* Archive Status Banner */}
                  {webArch.archived ? (
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 bg-blue-50/70 border border-blue-200 rounded-xl gap-3">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0">
                          <Archive className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-bold text-slate-900">Wayback Machine Archive Record</h4>
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                              Archived
                            </span>
                          </div>
                          <p className="text-xs text-slate-600 mt-0.5">
                            Historical snapshots recorded by the Internet Archive Wayback Machine for <span className="font-mono font-medium text-slate-800">{cleanTarget}</span>
                          </p>
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        <a
                          href={waybackHttpUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm transition shrink-0"
                        >
                          <span>Open Wayback Calendar</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={archiveTodayUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 text-xs font-medium rounded-lg shadow-xs transition shrink-0"
                        >
                          <span>Archive.today</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  ) : webArch.api_status === 'service_unavailable' ? (
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 bg-amber-50/80 border border-amber-200 rounded-xl gap-3">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-lg bg-amber-600 text-white flex items-center justify-center shrink-0">
                          <AlertTriangle className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-bold text-amber-950">Wayback Machine Unreachable / Offline Maintenance</h4>
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-900 border border-amber-300">
                              API Offline (Use Mirrors)
                            </span>
                          </div>
                          <p className="text-xs text-amber-900/90 mt-0.5 leading-relaxed">
                            The Internet Archive cluster is actively refusing connections or experiencing downtime. While Archive.org is offline, you can view snapshots on active alternative archives below:
                          </p>
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        <a
                          href={archiveTodayUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm transition shrink-0"
                          title="Independent active archive mirror"
                        >
                          <span>Search Archive.today</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={urlscanUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-900 text-white text-xs font-medium rounded-lg shadow-sm transition shrink-0"
                          title="View historical security scans on urlscan.io"
                        >
                          <span>URLScan.io History</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={waybackHttpUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-amber-100 hover:bg-amber-200 border border-amber-300 text-amber-900 text-xs font-medium rounded-lg transition shrink-0"
                          title="Official Wayback Calendar (may refuse connections if server is down)"
                        >
                          <span>Wayback Calendar</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  ) : (
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 bg-slate-50 border border-slate-200 rounded-xl gap-3">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-lg bg-slate-200 text-slate-600 flex items-center justify-center shrink-0">
                          <Archive className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-bold text-slate-800">No Automated Archive Snapshots Returned</h4>
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 text-slate-600 border border-slate-300">
                              Unindexed
                            </span>
                          </div>
                          <p className="text-xs text-slate-500 mt-0.5">
                            No automated snapshots returned for apex domain {cleanTarget}. Check canonical variations or subpaths directly.
                          </p>
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        <a
                          href={waybackHttpUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 text-xs font-medium rounded-lg transition shrink-0"
                        >
                          <span>Search Wayback Machine</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  )}

                  {/* Timeline Header */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">First Seen in Archive</span>
                      <p className="text-xs font-bold font-mono text-slate-800 mt-1">
                        {webArch.first_seen || (webArch.archived ? 'Indexed in Wayback Machine' : webArch.api_status === 'service_unavailable' ? 'API Offline (Check Calendar)' : 'Not Indexed')}
                      </p>
                    </div>
                    <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Last Seen in Archive</span>
                      <p className="text-xs font-bold font-mono text-slate-800 mt-1">
                        {webArch.last_seen || (webArch.archived ? 'Recorded in Archive' : webArch.api_status === 'service_unavailable' ? 'API Offline (Check Calendar)' : 'Not Indexed')}
                      </p>
                    </div>
                    <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Total Historic Snapshots</span>
                      <p className="text-base font-extrabold text-blue-700 mt-0.5">
                        {webArch.snapshot_count > 0 ? webArch.snapshot_count : (webArch.archived ? '1+' : webArch.api_status === 'service_unavailable' ? 'Inspect Calendar' : 0)}
                      </p>
                    </div>
                    <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Historic Archive Span</span>
                      <p className="text-xs font-bold font-mono text-slate-800 mt-1">
                        {webArch.age_days ? `${Math.round(webArch.age_days / 365)} Years (${webArch.age_days} days)` : (webArch.archived ? 'Multiple Snapshots' : webArch.api_status === 'service_unavailable' ? 'Historical Timeline' : 'N/A')}
                      </p>
                    </div>
                  </div>

                  {/* Dormant Revival Warning */}
                  {webArch.dormant_revival_detected && (
                    <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-rose-950 flex items-start gap-3">
                      <Flame className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                      <div>
                        <h5 className="text-xs font-bold uppercase tracking-wider">Dormant Domain Revival / Repurposing Detected</h5>
                        <p className="text-xs mt-0.5 leading-relaxed">
                          This domain had an inactivity gap of over {Math.round((webArch.revival_gap_days || 730) / 365)} years before recent re-activation. Threat actors frequently buy expired domains with positive legacy SEO reputation to deploy spear-phishing or C2 channels.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Recent Snapshots Table */}
                  {webArch.recent_snapshots && webArch.recent_snapshots.length > 0 ? (
                    <div className="border border-slate-200 rounded-xl overflow-hidden">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                          <tr>
                            <th className="py-2.5 px-4">Snapshot Date</th>
                            <th className="py-2.5 px-4">Status</th>
                            <th className="py-2.5 px-4">Content Type</th>
                            <th className="py-2.5 px-4 text-right">Wayback Machine</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {webArch.recent_snapshots.map((snap, idx) => (
                            <tr key={idx} className="hover:bg-slate-50/50">
                              <td className="py-2 px-4 text-slate-800 font-medium">{snap.date}</td>
                              <td className="py-2 px-4">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  snap.status_code === '200' ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-700'
                                }`}>
                                  HTTP {snap.status_code}
                                </span>
                              </td>
                              <td className="py-2 px-4 text-slate-500">{snap.mimetype || 'text/html'}</td>
                              <td className="py-2 px-4 text-right">
                                <a
                                  href={snap.archive_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-xs font-medium"
                                >
                                  <span>Inspect Snapshot</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500 space-y-3">
                      <p>
                        {webArch.api_status === 'service_unavailable'
                          ? 'Internet Archive API is temporarily offline or timed out. Snapshots could not be retrieved via automated query.'
                          : 'No historical snapshots returned for apex query. Check canonical variations below.'}
                      </p>
                      <div className="flex flex-wrap items-center justify-center gap-2">
                        <a
                          href={archiveTodayUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold shadow-xs transition"
                        >
                          <span>Search Archive.today (Working Mirror)</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={urlscanUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold shadow-xs transition"
                        >
                          <span>URLScan.io History</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={waybackHttpUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 rounded-lg text-xs font-medium transition"
                        >
                          <span>Wayback Calendar (http://{cleanTarget}*)</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <a
                          href={waybackHttpsUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 rounded-lg text-xs font-medium transition"
                        >
                          <span>HTTPS Variant</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        {!cleanTarget.startsWith('www.') && (
                          <a
                            href={waybackWwwUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 rounded-lg text-xs font-medium transition"
                          >
                            <span>www.{cleanTarget} Variant</span>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        )}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                  Historical web archive inspection pending.
                </div>
              )}

            {/* Investigation Snapshot Comparison (Time-Series Delta Tracking) */}
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <GitCompare className="w-4 h-4 text-blue-600" />
                    <span>Investigation Snapshot Delta Tracker</span>
                  </h4>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Tracks infrastructure drift, DNS churn, SSL renewals, and subdomain expansions over time against historical investigation baselines.
                  </p>
                </div>
                {snapshotDiff?.has_historical_baseline ? (
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                    (snapshotDiff.total_changes_detected || 0) > 0
                      ? 'bg-amber-100 text-amber-800 border-amber-300'
                      : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                  }`}>
                    {(snapshotDiff.total_changes_detected || 0) > 0
                      ? `${snapshotDiff.total_changes_detected} Changes Detected`
                      : 'Infrastructure Stable (No Drift)'}
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                    Baseline Snapshot
                  </span>
                )}
              </div>

              {snapshotDiff?.has_historical_baseline ? (
                <div className="space-y-3 pt-1">
                  {/* Delta Highlights Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">IP Shifts</span>
                      <p className={`font-bold mt-0.5 ${snapshotDiff.delta_summary?.ip_changed ? 'text-amber-700' : 'text-slate-700'}`}>
                        {snapshotDiff.delta_summary?.ip_changed ? 'Rotated' : 'Unchanged'}
                      </p>
                      {snapshotDiff.delta_summary?.added_ips && snapshotDiff.delta_summary.added_ips.length > 0 && (
                        <p className="text-[10px] text-emerald-600 font-mono truncate">+{snapshotDiff.delta_summary.added_ips.join(', ')}</p>
                      )}
                    </div>
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">Nameservers</span>
                      <p className={`font-bold mt-0.5 ${snapshotDiff.delta_summary?.ns_changed ? 'text-amber-700' : 'text-slate-700'}`}>
                        {snapshotDiff.delta_summary?.ns_changed ? 'Swapped' : 'Unchanged'}
                      </p>
                    </div>
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">TLS Certificate</span>
                      <p className={`font-bold mt-0.5 ${snapshotDiff.delta_summary?.cert_changed ? 'text-blue-700' : 'text-slate-700'}`}>
                        {snapshotDiff.delta_summary?.cert_changed ? 'Renewed / Changed' : 'Unchanged'}
                      </p>
                    </div>
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                      <span className="text-[10px] font-bold text-slate-500 uppercase">New Subdomains</span>
                      <p className="font-bold mt-0.5 text-indigo-700">
                        +{snapshotDiff.delta_summary?.new_subdomains_count || 0}
                      </p>
                    </div>
                  </div>

                  {/* Timeline Events */}
                  {snapshotDiff.timeline_events && snapshotDiff.timeline_events.length > 0 && (
                    <div className="space-y-1.5 pt-2">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-700 block">
                        Drift Events Timeline
                      </span>
                      {snapshotDiff.timeline_events.map((evt, idx) => (
                        <div key={idx} className="p-2.5 bg-white rounded-lg border border-slate-200 flex items-start gap-2.5">
                          <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                            evt.severity === 'high' ? 'bg-rose-500' :
                            evt.severity === 'medium' ? 'bg-amber-500' : 'bg-blue-500'
                          }`} />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-bold text-slate-900">{evt.title}</span>
                              {evt.timestamp && (
                                <span className="text-[10px] font-mono text-slate-400">{evt.timestamp}</span>
                              )}
                            </div>
                            <p className="text-xs text-slate-600 mt-0.5">{evt.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-3 bg-white rounded-lg border border-slate-200 text-xs text-slate-600 flex items-center gap-2">
                  <Info className="w-4 h-4 text-blue-500 shrink-0" />
                  <span>
                    Initial baseline snapshot captured for this asset in this workspace. Subsequent automated or manual re-scans will track infrastructure changes, IP rotations, certificate renewals, and subdomain expansions.
                  </span>
                </div>
              )}
            </div>
          </div>
        );
      })()}

        {/* ================= TAB: BGP ROUTING, RPKI & PASSIVE DNS ================= */}
        {activeTab === 'bgp_pdns' && (
          <div className="space-y-6">
            {/* BGP & RPKI Routing Card */}
            {bgpRouting && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <Compass className="w-4 h-4 text-blue-600" />
                    <span>BGP Route Origin &amp; RPKI Validation</span>
                  </h5>
                  <div className="flex items-center gap-2">
                    {bgpRouting.is_anycast && (
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-100 text-purple-800 border border-purple-200">
                        {bgpRouting.anycast_provider || 'Anycast CDN'}
                      </span>
                    )}
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                      bgpRouting.rpki_status === 'valid'
                        ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                        : bgpRouting.rpki_status === 'invalid'
                        ? 'bg-rose-100 text-rose-800 border-rose-300'
                        : 'bg-amber-100 text-amber-800 border-amber-300'
                    }`}>
                      RPKI: {bgpRouting.rpki_status.toUpperCase()}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block text-[10px]">Announced Prefix</span>
                    <span className="font-bold text-slate-800">{bgpRouting.prefix || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">Origin ASN</span>
                    <span className="font-bold text-slate-800">{bgpRouting.asn || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px]">BGP Visibility Ratio</span>
                    <span className="font-bold text-slate-800">
                      {bgpRouting.bgp_visibility?.visibility_ratio ? `${(bgpRouting.bgp_visibility.visibility_ratio * 100).toFixed(1)}%` : 'Active'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Passive DNS */}
            {pDns && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <Server className="w-4 h-4 text-blue-600" />
                    <span>Passive DNS (pDNS) Co-Location &amp; Historical Resolutions ({pDns.total_records})</span>
                  </h5>
                  <span className="text-xs text-slate-400 font-mono">Sources: {(pDns.sources || []).join(', ')}</span>
                </div>

                {pDns.records && pDns.records.length > 0 ? (
                  <div className="border border-slate-200 rounded-xl overflow-hidden max-h-80 overflow-y-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px] sticky top-0">
                        <tr>
                          <th className="py-2.5 px-4">Hostname</th>
                          <th className="py-2.5 px-4">IP Address</th>
                          <th className="py-2.5 px-4">Type</th>
                          <th className="py-2.5 px-4">Seen Period</th>
                          <th className="py-2.5 px-4 text-right">Pivot</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {pDns.records.slice(0, 30).map((r, i) => (
                          <tr key={i} className="hover:bg-slate-50/50">
                            <td className="py-2 px-4 font-bold text-slate-900 truncate max-w-xs">{r.hostname}</td>
                            <td className="py-2 px-4 text-slate-600">{r.address}</td>
                            <td className="py-2 px-4 text-slate-400">{r.record_type}</td>
                            <td className="py-2 px-4 text-slate-400 text-[10px]">
                              {r.first_seen ? `${r.first_seen.split('T')[0]} → ${r.last_seen?.split('T')[0] || 'now'}` : 'Recent'}
                            </td>
                            <td className="py-2 px-4 text-right">
                              <InvestigateAssetButton
                                ioc={r.hostname}
                                iocType="domain"
                                compact={true}
                                onNavigateToJob={onNavigateToJob}
                              />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No passive DNS records found.</p>
                )}
              </div>
            )}

            {/* Public Paste & Leak Exposure */}
            {leakSearch && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <FileCode className="w-4 h-4 text-blue-600" />
                    <span>Public Pastebin &amp; Leak Repository Exposure</span>
                  </h5>
                  <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                    leakSearch.severity === 'HIGH'
                      ? 'bg-rose-100 text-rose-800 border-rose-300'
                      : leakSearch.severity === 'MEDIUM'
                      ? 'bg-amber-100 text-amber-800 border-amber-300'
                      : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                  }`}>
                    {leakSearch.has_leaks ? `${leakSearch.leak_count} LEAK MENTIONS` : 'NO PUBLIC LEAKS DETECTED'}
                  </span>
                </div>

                {leakSearch.leaks && leakSearch.leaks.length > 0 ? (
                  <div className="space-y-2">
                    {leakSearch.leaks.map((leak, lidx) => (
                      <div key={lidx} className="p-2.5 bg-white border border-slate-200 rounded-lg text-xs flex items-center justify-between">
                        <span className="font-mono text-slate-800">Paste #{leak.id} ({leak.date || 'unknown date'})</span>
                        <div className="flex items-center gap-2">
                          {(leak.tags || []).map((t, tidx) => (
                            <span key={tidx} className="px-1.5 py-0.2 bg-slate-100 text-slate-600 rounded text-[10px] font-mono">
                              {t}
                            </span>
                          ))}
                          {leak.url && (
                            <a href={leak.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:text-blue-800">
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">No target credentials or configuration dumps indexed in public paste repositories.</p>
                )}
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: ACTIVE SECURITY RECON ================= */}
        {activeTab === 'recon' && (
          <div className="space-y-6">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-blue-600" />
                  <span>Controlled Active Security Audit</span>
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Executes bounded TCP service checks, sensitive file exposure prober (/.git, /.env), WAF detection, CORS misconfiguration check, TLS weaknesses, and SMTP relay verification.
                </p>
              </div>

              {jobId && (
                <button
                  onClick={handleTriggerActiveRecon}
                  disabled={isScanningPorts}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-xs transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {isScanningPorts ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Auditing Security...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-3.5 h-3.5" />
                      <span>Authorize &amp; Run Active Audit</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {scanMessage && (
              <div className="p-3 bg-blue-50 border border-blue-200 rounded-xl text-xs text-blue-800 flex items-center gap-2">
                <Info className="w-4 h-4 text-blue-600 shrink-0" />
                <span>{scanMessage}</span>
              </div>
            )}

            {/* Active Probes Results */}
            {activeProbes && activeProbes.executed && (
              <div className="space-y-4">
                {/* Sensitive Files Exposure */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Bug className="w-3.5 h-3.5 text-rose-600" />
                      <span>Sensitive File &amp; Secret Exposure</span>
                    </h5>
                    <span className="text-xs font-mono text-slate-500">Tested {activeProbes.sensitive_files?.tested || 9} paths</span>
                  </div>
                  {activeProbes.sensitive_files?.exposed && activeProbes.sensitive_files.exposed.length > 0 ? (
                    <div className="space-y-2">
                      {activeProbes.sensitive_files.exposed.map((exp, idx) => (
                        <div key={idx} className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-900 flex items-start justify-between gap-3">
                          <div>
                            <span className="font-bold font-mono">{exp.path}</span> — <span>{exp.title}</span>
                            {exp.content_preview && (
                              <p className="mt-1 font-mono text-[11px] text-rose-800 bg-white/80 p-1.5 rounded border border-rose-200 truncate max-w-xl">
                                {exp.content_preview}
                              </p>
                            )}
                          </div>
                          <span className="px-2 py-0.5 bg-rose-200 text-rose-900 rounded font-bold text-[10px] uppercase">
                            {exp.risk}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs font-mono text-emerald-700 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      No critical files (/.git, /.env, /backup.zip, etc.) publicly exposed.
                    </p>
                  )}
                </div>

                {/* 4-column Security Probes Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {/* WAF */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">WAF &amp; Reverse Proxy</span>
                    <p className="text-xs font-bold text-slate-800 truncate" title={activeProbes.waf_detection?.waf_name || ''}>
                      {activeProbes.waf_detection?.detected ? activeProbes.waf_detection.waf_name : 'No WAF Detected'}
                    </p>
                    <p className="text-[11px] text-slate-500">
                      Active probe blocked: {activeProbes.waf_detection?.blocked_test ? 'Yes (Shielded)' : 'No'}
                    </p>
                  </div>

                  {/* CORS */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">CORS &amp; HTTP Methods</span>
                    <p className={`text-xs font-bold ${activeProbes.cors_and_methods?.cors_misconfigured ? 'text-rose-600' : 'text-slate-800'}`}>
                      {activeProbes.cors_and_methods?.cors_misconfigured ? 'Insecure CORS Policy' : 'Secure CORS Configuration'}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono truncate">
                      Methods: {(activeProbes.cors_and_methods?.methods_allowed || ['GET', 'POST']).join(', ')}
                    </p>
                  </div>

                  {/* TLS Cryptography Protocols */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">TLS Protocols Audit</span>
                    <p className={`text-xs font-bold ${activeProbes.tls_cryptography?.deprecated_protocols_found?.length ? 'text-rose-600' : 'text-slate-800'}`}>
                      {activeProbes.tls_cryptography?.deprecated_protocols_found?.length
                        ? `Deprecated: ${activeProbes.tls_cryptography.deprecated_protocols_found.join(', ')}`
                        : 'Modern Protocols Active'}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono">
                      TLS 1.2: {activeProbes.tls_cryptography?.protocols?.TLSv1_2 ? 'Enabled' : 'Off'} • 1.3: {activeProbes.tls_cryptography?.protocols?.TLSv1_3 ? 'Enabled' : 'Off'}
                    </p>
                  </div>

                  {/* SMTP Relay */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">SMTP Relay &amp; STARTTLS</span>
                    <p className={`text-xs font-bold ${activeProbes.smtp_relay_starttls?.open_relay ? 'text-rose-600' : 'text-slate-800'}`}>
                      {activeProbes.smtp_relay_starttls?.tested
                        ? activeProbes.smtp_relay_starttls.open_relay
                          ? 'VULNERABLE OPEN RELAY'
                          : 'Relay Rejected (Secure)'
                        : 'No MX Tested'}
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono">
                      STARTTLS: {activeProbes.smtp_relay_starttls?.starttls_supported ? 'Supported' : 'Unadvertised'}
                    </p>
                  </div>
                </div>

                {/* Discovered API Endpoints */}
                {activeProbes.api_endpoints?.discovered && activeProbes.api_endpoints.discovered.length > 0 && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
                      Discovered API &amp; Schema Documentation
                    </h5>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                      {activeProbes.api_endpoints.discovered.map((api, idx) => (
                        <div key={idx} className="p-2 bg-white border border-slate-200 rounded-lg flex items-center justify-between">
                          <span className="font-bold text-slate-800">{api.path}</span>
                          <span className="text-blue-600 text-[11px]">{api.type}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Standard Open Ports (Nmap Service Scan) */}
            {activeRecon?.services && activeRecon.services.length > 0 ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-700">Open Services &amp; Daemons</span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-800">
                      {activeRecon.open_ports_count || activeRecon.services.length} Open
                    </span>
                    {activeRecon.scanner === 'nmap' && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-purple-50 text-purple-700 border border-purple-200">
                        <Terminal className="w-3 h-3" />
                        Nmap -sS -sV
                      </span>
                    )}
                  </div>
                </div>

                <div className="border border-slate-200 rounded-xl overflow-hidden shadow-xs">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                      <tr>
                        <th className="py-2.5 px-4">Port</th>
                        <th className="py-2.5 px-4">Protocol</th>
                        <th className="py-2.5 px-4">Service</th>
                        <th className="py-2.5 px-4">Status</th>
                        <th className="py-2.5 px-4">Reason</th>
                        <th className="py-2.5 px-4">Detected Software / Live Banner</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {activeRecon.services.map((svc, i) => (
                        <tr key={i} className="hover:bg-slate-50/50">
                          <td className="py-2.5 px-4 font-bold text-slate-900">{svc.port}</td>
                          <td className="py-2.5 px-4 text-slate-500">{svc.protocol}</td>
                          <td className="py-2.5 px-4 font-semibold text-blue-700">{svc.service}</td>
                          <td className="py-2.5 px-4">
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800">
                              OPEN
                            </span>
                          </td>
                          <td className="py-2.5 px-4">
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-700 font-mono">
                              {svc.reason || 'syn-ack'}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-slate-700 max-w-sm">
                            <div className="truncate font-sans font-medium" title={svc.banner || ''}>
                              {svc.banner || '<no banner returned>'}
                            </div>
                            {(svc.product || svc.version) && (
                              <div className="text-[10px] text-slate-500 font-mono truncate">
                                {[svc.product, svc.version, svc.extrainfo].filter(Boolean).join(' ')}
                              </div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Collapsible Raw Nmap Scan Output */}
                {(activeRecon.raw_nmap || activeRecon.scan_command) && (
                  <details className="group border border-slate-200 rounded-xl overflow-hidden bg-slate-50/60 transition-all">
                    <summary className="flex items-center justify-between px-4 py-2.5 cursor-pointer select-none text-xs font-semibold text-slate-700 hover:bg-slate-100/70">
                      <div className="flex items-center gap-2">
                        <Terminal className="w-3.5 h-3.5 text-slate-500" />
                        <span>Nmap Execution Command &amp; Raw Output</span>
                      </div>
                      <ChevronDown className="w-4 h-4 text-slate-400 group-open:rotate-180 transition-transform duration-200" />
                    </summary>
                    <div className="p-4 pt-2 border-t border-slate-200 bg-white space-y-2">
                      {activeRecon.scan_command && (
                        <div>
                          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">Executed Command:</div>
                          <code className="block p-2 bg-slate-900 text-purple-300 font-mono text-[11px] rounded-md overflow-x-auto select-all">
                            {activeRecon.scan_command}
                          </code>
                        </div>
                      )}
                      {activeRecon.raw_nmap && (
                        <div>
                          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">Raw Nmap Output (-oA nmap-service-scan):</div>
                          <pre className="p-3 bg-slate-950 text-emerald-400 font-mono text-[11px] rounded-md overflow-x-auto max-h-64 whitespace-pre">
                            {activeRecon.raw_nmap}
                          </pre>
                        </div>
                      )}
                    </div>
                  </details>
                )}
              </div>
            ) : (
              <div className="p-8 border border-dashed border-slate-300 rounded-xl text-center text-xs text-slate-500 space-y-1">
                <p className="font-semibold text-slate-700">No active scan has been executed yet.</p>
                <p>Click &quot;Authorize &amp; Run Active Audit&quot; above to discover open web, mail, and management services via Nmap.</p>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: ATTACK SURFACE & SUBDOMAINS ================= */}
        {activeTab === 'surface' && (
          <div className="space-y-5">
            {/* Header & Metric Badges */}
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Radio className="w-4 h-4 text-blue-600" />
                  <span>Subdomain Attack Surface &amp; Topology</span>
                </h4>
                <p className="text-xs text-slate-600 mt-0.5">
                  Discovered {surface?.total_discovered || 0} subdomains via Certificate Transparency (crt.sh), TLS SANs, DNS CNAMEs, and active probes.
                </p>
              </div>

              {/* Status Counters */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 mr-1.5 animate-pulse"></span>
                  {surface?.active_count || 0} Active (Resolving)
                </span>
                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-700 border border-slate-300">
                  <span className="w-2 h-2 rounded-full bg-slate-400 mr-1.5"></span>
                  {surface?.dormant_count || 0} Unresolved (Dormant)
                </span>
              </div>
            </div>

            {/* "Why are some subdomains unresolved?" Explanatory Banner */}
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 text-xs">
              <div className="flex items-center justify-between cursor-pointer" onClick={() => setShowUnresolvedExplanation(!showUnresolvedExplanation)}>
                <div className="flex items-center gap-2 font-bold text-slate-800">
                  <Info className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>Why are some subdomains listed as &quot;Unresolved&quot;?</span>
                </div>
                <button
                  type="button"
                  className="text-xs text-blue-600 hover:text-blue-800 font-semibold"
                >
                  {showUnresolvedExplanation ? 'Hide Guide' : 'Show Guide'}
                </button>
              </div>

              {showUnresolvedExplanation && (
                <div className="mt-3 pt-3 border-t border-slate-200 text-slate-600 space-y-2 leading-relaxed">
                  <p>
                    In cyber threat intelligence and passive reconnaissance, subdomains are gathered from multiple historical and public datasets. An <strong>Unresolved (Dormant)</strong> status indicates that public DNS resolvers currently return <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200 font-mono text-[11px] text-slate-800">NXDOMAIN</code> (no A or AAAA address) for that hostname.
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                      <span className="font-bold text-slate-800 block text-[11px] uppercase tracking-wider">1. Historical CT Logs (crt.sh)</span>
                      <p className="text-[11px] text-slate-500">
                        When SSL certificates are created for dev, staging, or test environments, they are permanently recorded in public append-only transparency logs. When the server or DNS record is later decommissioned, the certificate remains in log history forever.
                      </p>
                    </div>
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                      <span className="font-bold text-slate-800 block text-[11px] uppercase tracking-wider">2. Split-Horizon / Internal DNS</span>
                      <p className="text-[11px] text-slate-500">
                        Corporate services (e.g. <span className="font-mono">vpn.</span>, <span className="font-mono">jira.</span>, <span className="font-mono">corp.</span>) are often included on public TLS certificates, but their DNS resolution is restricted exclusively to private internal networks (RFC 1918).
                      </p>
                    </div>
                    <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                      <span className="font-bold text-slate-800 block text-[11px] uppercase tracking-wider">3. Wordlists &amp; Takeovers</span>
                      <p className="text-[11px] text-slate-500">
                        Common speculative prefixes probed that do not exist on the zone, or abandoned third-party cloud records (e.g., S3, Azure, GitHub Pages) whose backing service was deleted.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Filter and View Controls */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
              <div className="flex items-center gap-2 flex-wrap">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={subdomainSearch}
                    onChange={e => setSubdomainSearch(e.target.value)}
                    placeholder="Search subdomain or IP..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-mono w-56"
                  />
                </div>

                {/* Status Filter */}
                <select
                  value={subdomainStatusFilter}
                  onChange={e => setSubdomainStatusFilter(e.target.value as any)}
                  className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 font-medium focus:outline-hidden"
                >
                  <option value="all">All Statuses ({surface?.total_discovered || 0})</option>
                  <option value="active">Active Only ({surface?.active_count || 0})</option>
                  <option value="unresolving">Unresolved Only ({surface?.dormant_count || 0})</option>
                </select>

                {/* Source Filter */}
                <select
                  value={subdomainSourceFilter}
                  onChange={e => setSubdomainSourceFilter(e.target.value)}
                  className="px-2.5 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-700 font-medium focus:outline-hidden"
                >
                  <option value="all">All Discovery Sources</option>
                  <option value="Certificate Transparency">Certificate Transparency</option>
                  <option value="Live TLS SAN">Live TLS SANs</option>
                  <option value="DNS CNAME">DNS CNAME Chain</option>
                  <option value="Passive DNS">Passive DNS / Sibling</option>
                  <option value="DNS Wordlist">DNS Wordlist Probes</option>
                </select>
              </div>

              <div className="flex items-center gap-2 self-end sm:self-center">
                <span className="text-xs text-slate-500 font-mono">
                  Showing {filteredSubdomains.length} of {surface?.total_discovered || 0}
                </span>
                <div className="flex items-center border border-slate-200 rounded-lg overflow-hidden bg-slate-50 p-0.5">
                  <button
                    onClick={() => setSubdomainViewMode('table')}
                    className={`px-2 py-1 text-xs font-semibold rounded cursor-pointer ${
                      subdomainViewMode === 'table' ? 'bg-white shadow-2xs text-blue-600' : 'text-slate-600'
                    }`}
                  >
                    Table
                  </button>
                  <button
                    onClick={() => setSubdomainViewMode('grid')}
                    className={`px-2 py-1 text-xs font-semibold rounded cursor-pointer ${
                      subdomainViewMode === 'grid' ? 'bg-white shadow-2xs text-blue-600' : 'text-slate-600'
                    }`}
                  >
                    Grid
                  </button>
                </div>
              </div>
            </div>

            {/* Subdomain Content: Table View vs Grid View */}
            {filteredSubdomains.length > 0 ? (
              subdomainViewMode === 'table' ? (
                <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                      <tr>
                        <th className="py-2.5 px-4">Subdomain Hostname</th>
                        <th className="py-2.5 px-4">Resolution Status</th>
                        <th className="py-2.5 px-4">Discovered From (Source)</th>
                        <th className="py-2.5 px-4">Resolved IP(s)</th>
                        <th className="py-2.5 px-4 text-right">Workspace Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {filteredSubdomains.map((sub, i) => (
                        <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                          <td className="py-2.5 px-4">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-900 truncate max-w-xs" title={sub.subdomain}>
                                {sub.subdomain}
                              </span>
                              {sub.is_root && (
                                <span className="px-1.5 py-0.2 bg-blue-100 text-blue-800 rounded text-[10px] font-sans font-bold">
                                  Root Target
                                </span>
                              )}
                              <button
                                onClick={() => copyToClipboard(sub.subdomain, `sub-${i}`)}
                                className="text-slate-400 hover:text-slate-700 cursor-pointer"
                                title="Copy hostname"
                              >
                                {copiedKey === `sub-${i}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          </td>
                          <td className="py-2.5 px-4">
                            {sub.status === 'active' ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5 animate-pulse"></span>
                                Active (Resolving)
                              </span>
                            ) : (
                              <div>
                                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-100 text-slate-700 border border-slate-300">
                                  Unresolved (Dormant)
                                </span>
                                {sub.unresolving_reason && (
                                  <p className="text-[10px] text-slate-500 italic mt-0.5 max-w-xs leading-tight" title={sub.unresolving_reason}>
                                    {sub.unresolving_reason}
                                  </p>
                                )}
                              </div>
                            )}
                          </td>
                          <td className="py-2.5 px-4">
                            <div className="flex items-center gap-1 flex-wrap">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-sans font-semibold border ${
                                sub.discovered_from?.includes('Certificate')
                                  ? 'bg-indigo-50 border-indigo-200 text-indigo-800'
                                  : sub.discovered_from?.includes('SAN')
                                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                                  : sub.discovered_from?.includes('CNAME')
                                  ? 'bg-blue-50 border-blue-200 text-blue-800'
                                  : sub.discovered_from?.includes('Passive')
                                  ? 'bg-purple-50 border-purple-200 text-purple-800'
                                  : 'bg-slate-100 border-slate-200 text-slate-700'
                              }`}>
                                {sub.discovered_from || 'Passive Discovery'}
                              </span>
                              {sub.sources && sub.sources.length > 1 && (
                                <span className="text-[10px] text-slate-400 font-sans" title={`Sources: ${sub.sources.join(', ')}`}>
                                  +{sub.sources.length - 1} more
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-4 font-mono text-xs">
                            {sub.ips && sub.ips.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {sub.ips.slice(0, 2).map((ip, ipIdx) => (
                                  <span key={ipIdx} className="px-1.5 py-0.5 bg-white border border-slate-200 rounded text-[11px] text-slate-800 shadow-2xs">
                                    {ip}
                                  </span>
                                ))}
                                {sub.ips.length > 2 && (
                                  <span className="text-[10px] text-slate-400 self-center">
                                    +{sub.ips.length - 2}
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-slate-400 text-xs">NXDOMAIN</span>
                            )}
                          </td>
                          <td className="py-2.5 px-4 text-right">
                            <InvestigateAssetButton
                              ioc={sub.subdomain}
                              iocType="domain"
                              compact={true}
                              onNavigateToJob={onNavigateToJob}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
                  {filteredSubdomains.map((sub, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-xl border flex flex-col justify-between gap-2 shadow-2xs ${
                        sub.is_root
                          ? 'bg-blue-50/70 border-blue-200'
                          : sub.status === 'active'
                          ? 'bg-white border-slate-200'
                          : 'bg-slate-50/60 border-slate-200'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-bold text-slate-900" title={sub.subdomain}>
                            {sub.subdomain}
                          </span>
                          <InvestigateAssetButton
                            ioc={sub.subdomain}
                            iocType="domain"
                            compact={true}
                            onNavigateToJob={onNavigateToJob}
                          />
                        </div>
                        <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-semibold border ${
                            sub.status === 'active'
                              ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                              : 'bg-slate-100 text-slate-600 border-slate-200'
                          }`}>
                            {sub.status === 'active' ? 'Active' : 'Unresolved'}
                          </span>
                          <span className="px-2 py-0.5 bg-indigo-50 border border-indigo-200 text-indigo-800 text-[10px] font-sans rounded">
                            {sub.discovered_from || 'Passive Discovery'}
                          </span>
                        </div>
                        {sub.unresolving_reason && (
                          <p className="text-[10px] text-slate-500 italic mt-1.5 leading-tight">
                            {sub.unresolving_reason}
                          </p>
                        )}
                      </div>
                      {sub.ips && sub.ips.length > 0 && (
                        <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-100">
                          IP: {sub.ips.join(', ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )
            ) : (
              <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                <Radio className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                <p className="font-semibold text-slate-700">No subdomains match your filter criteria.</p>
                <p className="text-slate-400 mt-0.5">Try clearing filters or search terms.</p>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: TLS & CERTIFICATES ================= */}
        {activeTab === 'tls' && (
          <div className="space-y-6">
            {tls?.live_cert ? (
              <>
                {/* Live Certificate Hero Banner */}
                <div className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
                  tls.live_cert.is_expired
                    ? 'bg-rose-50 border-rose-200 text-rose-950'
                    : tls.live_cert.is_self_signed
                    ? 'bg-amber-50 border-amber-200 text-amber-950'
                    : tls.live_cert.days_remaining !== undefined && tls.live_cert.days_remaining < 14
                    ? 'bg-amber-50 border-amber-200 text-amber-950'
                    : 'bg-emerald-50 border-emerald-200 text-emerald-950'
                }`}>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Lock className="w-5 h-5 shrink-0" />
                      <h4 className="text-sm font-bold">
                        {tls.live_cert.is_expired
                          ? 'Expired SSL/TLS Certificate'
                          : tls.live_cert.is_self_signed
                          ? 'Self-Signed SSL/TLS Certificate'
                          : 'Valid & Active SSL/TLS Certificate'}
                      </h4>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-white/70 border border-current/20">
                        Port {tls.port || 443} • {tls.live_cert.tls_version || 'TLS'}
                      </span>
                    </div>
                    <p className="text-xs opacity-90">
                      Subject: <strong>{tls.live_cert.subject?.common_name || domainInfo.target}</strong>
                      {tls.live_cert.subject?.organization ? ` (${tls.live_cert.subject.organization})` : ''} • Issued by <strong>{tls.live_cert.issuer?.organization || tls.live_cert.issuer?.common_name || 'Public CA'}</strong>
                    </p>
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-xl font-extrabold">
                      {tls.live_cert.days_remaining !== undefined
                        ? (tls.live_cert.days_remaining >= 0 ? `${tls.live_cert.days_remaining} Days` : 'Expired')
                        : 'Active'}
                    </span>
                    <p className="text-[11px] opacity-80 font-mono">
                      {tls.live_cert.days_remaining !== undefined && tls.live_cert.days_remaining >= 0 ? 'Remaining Validity' : 'Past Expiration'}
                    </p>
                  </div>
                </div>

                {/* 3-Column Technical Specifications Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                  {/* Card 1: Subject & Authority */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                    <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] font-sans flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-blue-600" />
                      <span>Subject &amp; Authority</span>
                    </h5>
                    <div className="space-y-1.5">
                      <div>
                        <span className="text-slate-400 block text-[10px]">Common Name (CN)</span>
                        <span className="font-bold text-slate-800 break-all">{tls.live_cert.subject?.common_name || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Subject Organization</span>
                        <span className="text-slate-700">{tls.live_cert.subject?.organization || 'Unspecified'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Issuer Authority (CA)</span>
                        <span className="font-bold text-slate-800">{tls.live_cert.issuer?.organization || tls.live_cert.issuer?.common_name || 'Unknown CA'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Issuer Country</span>
                        <span className="text-slate-700">{tls.live_cert.issuer?.country || 'Global'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Card 2: Cryptographic Suite & Protocol */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                    <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] font-sans flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-blue-600" />
                      <span>Cipher Suite &amp; Protocol</span>
                    </h5>
                    <div className="space-y-1.5">
                      <div>
                        <span className="text-slate-400 block text-[10px]">Negotiated Protocol</span>
                        <span className="inline-block px-2 py-0.5 rounded font-bold bg-blue-100 text-blue-800 text-[11px]">
                          {tls.live_cert.tls_version || 'TLSv1.2/1.3'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Active Cipher Suite</span>
                        <span className="text-slate-800 break-all font-semibold">{tls.live_cert.cipher_suite || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Encryption Strength</span>
                        <span className="text-slate-700">{tls.live_cert.cipher_bits ? `${tls.live_cert.cipher_bits}-bit Symmetric Key` : 'Strong'}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Validity Period</span>
                        <span className="text-slate-600 text-[11px]">
                          {tls.live_cert.not_before?.split('T')[0] || 'N/A'} → {tls.live_cert.not_after?.split('T')[0] || 'N/A'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Card 3: Cryptographic Hashes & Serial */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                    <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] font-sans flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                      <span>Fingerprints &amp; Serial</span>
                    </h5>
                    <div className="space-y-2">
                      <div>
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-slate-400 text-[10px]">SHA-256 Fingerprint</span>
                          {tls.live_cert.sha256_fingerprint && (
                            <button
                              onClick={() => copyToClipboard(tls.live_cert?.sha256_fingerprint || '', 'sha256_cert')}
                              className="text-[10px] text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
                            >
                              {copiedKey === 'sha256_cert' ? <Check className="w-2.5 h-2.5 text-emerald-600" /> : <Copy className="w-2.5 h-2.5" />}
                              <span>{copiedKey === 'sha256_cert' ? 'Copied' : 'Copy'}</span>
                            </button>
                          )}
                        </div>
                        <p className="text-[10px] text-slate-700 bg-white p-1.5 rounded border border-slate-200 break-all select-all font-mono">
                          {tls.live_cert.sha256_fingerprint || 'N/A'}
                        </p>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="text-slate-400 text-[10px]">Serial Number</span>
                          {tls.live_cert.serial_number && (
                            <button
                              onClick={() => copyToClipboard(tls.live_cert?.serial_number || '', 'serial_cert')}
                              className="text-[10px] text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer"
                            >
                              {copiedKey === 'serial_cert' ? <Check className="w-2.5 h-2.5 text-emerald-600" /> : <Copy className="w-2.5 h-2.5" />}
                              <span>{copiedKey === 'serial_cert' ? 'Copied' : 'Copy'}</span>
                            </button>
                          )}
                        </div>
                        <p className="text-[10px] text-slate-700 bg-white p-1.5 rounded border border-slate-200 truncate select-all font-mono">
                          {tls.live_cert.serial_number || 'N/A'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Supported Cipher Suites & Cryptographic Posture Audit */}
                {(() => {
                  const cipherAudit = tls.cipher_suites_audit || tlsForensics?.cipher_suites_audit;
                  if (!cipherAudit || !cipherAudit.ciphers || cipherAudit.ciphers.length === 0) return null;
                  return (
                    <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3.5">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                          <h5 className="font-bold text-slate-800 uppercase tracking-wider text-xs flex items-center gap-1.5">
                            <Key className="w-3.5 h-3.5 text-blue-600" />
                            <span>Supported Cipher Suites &amp; Cryptographic Posture</span>
                          </h5>
                          <p className="text-[11px] text-slate-500 mt-0.5">
                            Audit of server-supported TLS cipher suites, Perfect Forward Secrecy (PFS) key exchanges, and vulnerability evaluations.
                          </p>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap self-start sm:self-auto">
                          <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-white text-slate-700 border border-slate-200 shadow-2xs">
                            {cipherAudit.supported_count} Supported
                          </span>
                          {cipherAudit.has_weak_ciphers ? (
                            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300 animate-pulse">
                              ⚠️ {cipherAudit.weak_ciphers_count} Insecure / Weak Supported
                            </span>
                          ) : (
                            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">
                              ✓ Modern Ciphers Enforced
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Weak Ciphers Warning Alert */}
                      {cipherAudit.has_weak_ciphers && (
                        <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-rose-900 text-xs flex items-start gap-2.5">
                          <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                          <div>
                            <strong className="font-bold">Cryptographic Downgrade &amp; Vulnerability Alert: </strong>
                            <span>
                              This server supports {cipherAudit.weak_ciphers_count} legacy or flawed cipher suite(s) ({cipherAudit.weak_ciphers.map(c => c.name).join(', ')}). Attackers on-path can force cipher downgrade, exploit CBC padding or Sweet32 collisions, or decrypt recorded traffic if static RSA keys are later compromised.
                            </span>
                          </div>
                        </div>
                      )}

                      {/* Supported Ciphers Table */}
                      <div className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                            <tr>
                              <th className="py-2.5 px-3">Cipher Suite Name</th>
                              <th className="py-2.5 px-2.5">Protocol</th>
                              <th className="py-2.5 px-2.5">Key Exchange / PFS</th>
                              <th className="py-2.5 px-2.5">Encryption / MAC</th>
                              <th className="py-2.5 px-2.5">Support Status</th>
                              <th className="py-2.5 px-2.5">Evaluation</th>
                              <th className="py-2.5 px-3">Why it is Bad or Good (Technical Flaw Analysis)</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {cipherAudit.ciphers.map((c, cIdx) => (
                              <tr
                                key={cIdx}
                                className={`transition-colors ${
                                  c.active_negotiated
                                    ? 'bg-blue-50/40 font-semibold'
                                    : c.is_weak && c.supported
                                    ? 'bg-rose-50/40 hover:bg-rose-50/70'
                                    : 'hover:bg-slate-50/50'
                                }`}
                              >
                                <td className="py-2 px-3 text-slate-800 break-all">
                                  <div className="flex items-center gap-1.5">
                                    <span>{c.name}</span>
                                    {c.active_negotiated && (
                                      <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-blue-100 text-blue-800 border border-blue-200">
                                        Active
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td className="py-2 px-2.5 text-slate-600 font-sans text-[11px] whitespace-nowrap">
                                  {c.protocol}
                                </td>
                                <td className="py-2 px-2.5 whitespace-nowrap font-sans text-[11px]">
                                  <span className={c.key_exchange.includes('PFS') ? 'text-emerald-700 font-semibold' : 'text-amber-700'}>
                                    {c.key_exchange}
                                  </span>
                                </td>
                                <td className="py-2 px-2.5 text-slate-600 font-sans text-[11px] whitespace-nowrap">
                                  {c.encryption} ({c.mac})
                                </td>
                                <td className="py-2 px-2.5 whitespace-nowrap">
                                  {c.supported ? (
                                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                                      Supported
                                    </span>
                                  ) : (
                                    <span className="px-2 py-0.5 rounded-full text-[10px] text-slate-400 bg-slate-100 border border-slate-200">
                                      Disabled
                                    </span>
                                  )}
                                </td>
                                <td className="py-2 px-2.5 whitespace-nowrap">
                                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                                    c.status === 'RECOMMENDED'
                                      ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                                      : c.status === 'ACCEPTABLE'
                                      ? 'bg-blue-100 text-blue-800 border-blue-200'
                                      : c.status === 'WEAK'
                                      ? 'bg-amber-100 text-amber-800 border-amber-300'
                                      : 'bg-rose-100 text-rose-800 border-rose-300'
                                  }`}>
                                    {c.status}
                                  </span>
                                </td>
                                <td className="py-2 px-3 text-[11px] font-sans leading-relaxed text-slate-700 max-w-md">
                                  <span className={c.is_weak ? 'text-rose-900 font-medium' : 'text-slate-600'}>
                                    {c.explanation}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })()}

                {/* Certificate Forensics & CT Log Audit */}
                {tlsForensics && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3.5 text-xs">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Certificate Forensics &amp; CT Log Audit</span>
                      </h5>
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider font-mono border ${
                        tlsForensics.matches_target
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                          : 'bg-rose-100 text-rose-800 border-rose-300 animate-pulse'
                      }`}>
                        {tlsForensics.matches_target ? '✓ RFC 6125 Valid Match' : '⚠ Hostname Mismatch Detected'}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <div className="p-2.5 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-[10px] uppercase font-bold text-slate-400">Hostname Matching</span>
                        <p className={`font-bold mt-0.5 ${tlsForensics.matches_target ? 'text-emerald-600' : 'text-rose-600'}`}>
                          {tlsForensics.matches_target ? 'Matches Target Name' : 'Hostname Mismatch'}
                        </p>
                      </div>
                      <div className="p-2.5 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-[10px] uppercase font-bold text-slate-400">Certificate Transparency</span>
                        <p className="font-bold text-slate-800 mt-0.5">{tlsForensics.ct_log_count || tls.ct_logs?.total_certificates_found || 0} CT Logs Seen</p>
                      </div>
                      <div className="p-2.5 bg-white rounded-lg border border-slate-200 shadow-2xs">
                        <span className="text-[10px] uppercase font-bold text-slate-400">Wildcard Certificate</span>
                        <p className="font-bold text-slate-800 mt-0.5">{tlsForensics.is_wildcard ? 'Wildcard (*.)' : 'Standard FQDN'}</p>
                      </div>
                    </div>

                    {/* In-depth Hostname Validation: How & Why Analysis Card */}
                    <div className={`p-4 rounded-xl border space-y-3 ${
                      tlsForensics.matches_target
                        ? 'bg-white border-emerald-200 shadow-2xs'
                        : 'bg-rose-50/50 border-rose-200 shadow-xs'
                    }`}>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-slate-100">
                        <div className="flex items-center gap-2">
                          {tlsForensics.matches_target ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          ) : (
                            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
                          )}
                          <span className="font-bold text-slate-900 text-xs">
                            Hostname Validation Diagnostics (RFC 6125 &amp; RFC 5280)
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px] font-mono">
                          <span className="text-slate-500">Target: <strong className="text-slate-800">{domainInfo.target}</strong></span>
                          <span className="text-slate-300">|</span>
                          <span className="text-slate-500">Cert CN: <strong className="text-slate-800">{tls.live_cert.subject?.common_name || 'N/A'}</strong></span>
                        </div>
                      </div>

                      {/* How & Why Callouts */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        {/* How it Matches / Mismatches */}
                        <div className="p-3 bg-slate-50/80 rounded-lg border border-slate-200/80 space-y-1">
                          <div className="flex items-center gap-1.5 text-slate-700 font-bold text-[11px] uppercase tracking-wider">
                            <Info className="w-3.5 h-3.5 text-blue-600" />
                            <span>How it {tlsForensics.matches_target ? 'Matches' : 'Mismatches'}</span>
                          </div>
                          <p className="text-slate-700 text-xs leading-relaxed font-sans">
                            {tlsForensics.hostname_validation?.how || (
                              tlsForensics.matches_target
                                ? `Requested hostname '${domainInfo.target}' matches the presented TLS certificate identity.`
                                : `Target '${domainInfo.target}' does not match certificate Subject Common Name ('${tls.live_cert.subject?.common_name || 'N/A'}') or any of its ${tls.live_cert.sans?.length || 0} Subject Alternative Names.`
                            )}
                          </p>
                        </div>

                        {/* Why this occurs and security implications */}
                        <div className={`p-3 rounded-lg border space-y-1 ${
                          tlsForensics.matches_target
                            ? 'bg-emerald-50/50 border-emerald-200/80 text-emerald-950'
                            : 'bg-rose-50/70 border-rose-200 text-rose-950'
                        }`}>
                          <div className="flex items-center gap-1.5 font-bold text-[11px] uppercase tracking-wider">
                            {tlsForensics.matches_target ? (
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                            ) : (
                              <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                            )}
                            <span className={tlsForensics.matches_target ? 'text-emerald-800' : 'text-rose-800'}>
                              Why &amp; Technical Root Cause
                            </span>
                          </div>
                          <p className="text-xs leading-relaxed font-sans">
                            {tlsForensics.hostname_validation?.why || (
                              tlsForensics.matches_target
                                ? 'RFC 6125 §6.4 establishes Subject Alternative Names (dNSName) as the primary authoritative identity for TLS validation. All modern browsers and HTTP clients accept this match unconditionally.'
                                : 'Under RFC 6125 §6.4.4 and CA/Browser Forum rules, connecting clients immediately abort connections when the requested hostname is not authorized by the certificate SAN extension (triggering ERR_CERT_COMMON_NAME_INVALID / SSL_ERROR_BAD_CERT_DOMAIN).'
                            )}
                          </p>
                        </div>
                      </div>

                      {/* Remediation & Guidance if mismatch */}
                      {!tlsForensics.matches_target && (
                        <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-start gap-2">
                          <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                          <div>
                            <span className="font-bold">Remediation Guidance: </span>
                            <span>{tlsForensics.hostname_validation?.remediation || 'Verify DNS A/AAAA records point to the correct web server, or reissue the TLS certificate with this domain added to the Subject Alternative Name (SAN) extension.'}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Subject Alternative Names (SANs) */}
                {tls.live_cert.sans && tls.live_cert.sans.length > 0 && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                      <h5 className="font-bold text-slate-700 uppercase tracking-wider text-xs flex items-center gap-1.5">
                        <Network className="w-3.5 h-3.5 text-blue-600" />
                        <span>Subject Alternative Names (SANs) ({tls.live_cert.sans.length})</span>
                      </h5>
                      {tls.live_cert.sans.length > 6 && (
                        <div className="relative">
                          <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-2" />
                          <input
                            type="text"
                            value={sanSearch}
                            onChange={e => setSanSearch(e.target.value)}
                            placeholder="Filter SAN domains..."
                            className="pl-7 pr-2.5 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-hidden font-mono w-48"
                          />
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 font-mono text-xs">
                      {tls.live_cert.sans
                        .filter(s => !sanSearch || s.toLowerCase().includes(sanSearch.toLowerCase()))
                        .slice(0, 60)
                        .map((san, idx) => (
                          <div key={idx} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between gap-2 shadow-2xs">
                            <span className="truncate text-slate-800" title={san}>{san}</span>
                            <InvestigateAssetButton
                              ioc={san.replace('*.', '')}
                              iocType="domain"
                              compact={true}
                              onNavigateToJob={onNavigateToJob}
                            />
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                {/* Certificate Transparency (CT) Historical Logs */}
                {tls.ct_logs && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <h5 className="font-bold text-slate-700 uppercase tracking-wider text-xs flex items-center gap-1.5">
                        <FileCode className="w-3.5 h-3.5 text-blue-600" />
                        <span>Public Certificate Transparency Logs (crt.sh)</span>
                      </h5>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-indigo-100 text-indigo-800 border border-indigo-200">
                        {tls.ct_logs.total_certificates_found || 0} Certificates Logged
                      </span>
                    </div>

                    {tls.ct_logs.issuers && tls.ct_logs.issuers.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Observed Certificate Authorities</span>
                        <div className="flex flex-wrap gap-1.5">
                          {tls.ct_logs.issuers.map((iss, iidx) => (
                            <span key={iidx} className="px-2 py-0.5 rounded-md text-[11px] bg-white border border-slate-200 text-slate-700 font-mono shadow-2xs">
                              {iss}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {tls.ct_logs.recent_entries && tls.ct_logs.recent_entries.length > 0 ? (
                      <div className="border border-slate-200 rounded-lg overflow-hidden bg-white">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                            <tr>
                              <th className="py-2 px-3">Entry ID</th>
                              <th className="py-2 px-3">Common Name</th>
                              <th className="py-2 px-3">Logged Date</th>
                              <th className="py-2 px-3">Validity</th>
                              <th className="py-2 px-3 text-right">crt.sh Link</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {tls.ct_logs.recent_entries.map((rentry, ridx) => (
                              <tr key={ridx} className="hover:bg-slate-50/50">
                                <td className="py-2 px-3 text-slate-500 font-bold">{rentry.id || 'N/A'}</td>
                                <td className="py-2 px-3 text-slate-800 font-semibold truncate max-w-xs">{rentry.common_name}</td>
                                <td className="py-2 px-3 text-slate-500">{rentry.logged_at ? rentry.logged_at.split('T')[0] : 'N/A'}</td>
                                <td className="py-2 px-3 text-slate-500">{rentry.not_before ? `${rentry.not_before.split('T')[0]} → ${rentry.not_after ? rentry.not_after.split('T')[0] : ''}` : 'N/A'}</td>
                                <td className="py-2 px-3 text-right">
                                  <a
                                    href={`https://crt.sh/?id=${rentry.id}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px]"
                                  >
                                    <span>Inspect</span>
                                    <ExternalLink className="w-2.5 h-2.5" />
                                  </a>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-500 font-mono">No recent CT log entries cataloged.</p>
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="space-y-4">
                <div className="p-6 border border-dashed border-slate-200 rounded-xl bg-slate-50/60 text-center space-y-2">
                  <Lock className="w-8 h-8 text-slate-300 mx-auto" />
                  <h5 className="text-sm font-bold text-slate-700">No Live TLS Certificate Captured on Port {tls?.port || 443}</h5>
                  <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
                    A passive TLS handshake to <code className="font-mono bg-white px-1 py-0.5 rounded border border-slate-200">{domainInfo.target}:{tls?.port || 443}</code> did not complete. The host may only serve cleartext HTTP (port 80), run TLS on a non-standard port (e.g. 8443), or enforce strict client IP geofencing.
                  </p>
                </div>

                {/* Show CT logs even if live port 443 handshake was absent */}
                {tls?.ct_logs?.total_certificates_found ? (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <h5 className="font-bold text-slate-700 uppercase tracking-wider text-xs flex items-center gap-1.5">
                        <FileCode className="w-3.5 h-3.5 text-blue-600" />
                        <span>Historical Certificate Transparency Records ({tls.ct_logs.total_certificates_found})</span>
                      </h5>
                      <span className="text-xs text-slate-500 font-mono">Found in public CT ledgers</span>
                    </div>
                    {tls.ct_logs.recent_entries && tls.ct_logs.recent_entries.length > 0 && (
                      <div className="border border-slate-200 rounded-lg overflow-hidden bg-white">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                            <tr>
                              <th className="py-2 px-3">Entry ID</th>
                              <th className="py-2 px-3">Common Name</th>
                              <th className="py-2 px-3">Logged Date</th>
                              <th className="py-2 px-3 text-right">crt.sh Link</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {tls.ct_logs.recent_entries.map((rentry, ridx) => (
                              <tr key={ridx} className="hover:bg-slate-50/50">
                                <td className="py-2 px-3 text-slate-500 font-bold">{rentry.id || 'N/A'}</td>
                                <td className="py-2 px-3 text-slate-800 font-semibold truncate max-w-xs">{rentry.common_name}</td>
                                <td className="py-2 px-3 text-slate-500">{rentry.logged_at ? rentry.logged_at.split('T')[0] : 'N/A'}</td>
                                <td className="py-2 px-3 text-right">
                                  <a
                                    href={`https://crt.sh/?id=${rentry.id}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px]"
                                  >
                                    <span>Inspect</span>
                                    <ExternalLink className="w-2.5 h-2.5" />
                                  </a>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                ) : null}
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: DNS & DNSSEC ================= */}
        {activeTab === 'dns' && (
          <div className="space-y-6">
            {/* 1. DNSSEC Cryptographic Validation Card */}
            <div className={`p-4 rounded-xl border ${
              advDns?.dnssec?.enabled
                ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                : 'bg-slate-50 border-slate-200 text-slate-800'
            }`}>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  {advDns?.dnssec?.enabled ? (
                    <div className="w-8 h-8 rounded-lg bg-emerald-100 border border-emerald-300 flex items-center justify-center text-emerald-700">
                      <ShieldCheck className="w-5 h-5" />
                    </div>
                  ) : (
                    <div className="w-8 h-8 rounded-lg bg-slate-200 border border-slate-300 flex items-center justify-center text-slate-600">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold">
                        {advDns?.dnssec?.enabled
                          ? 'DNSSEC Cryptographically Signed & Validated'
                          : 'DNSSEC Not Configured (Unsigned Zone)'}
                      </h4>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                        advDns?.dnssec?.enabled
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                          : 'bg-slate-200 text-slate-700 border-slate-300'
                      }`}>
                        {advDns?.dnssec?.enabled ? 'Protected' : 'Unsigned'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-0.5">
                      {advDns?.dnssec?.notes || (advDns?.dnssec?.enabled
                        ? 'Domain zone publishes DS records and valid cryptographic signatures against DNS cache poisoning.'
                        : 'Domain lacks DS delegation and RRSIG records. Responses can potentially be spoofed by adversary recursive resolvers.')}
                    </p>
                  </div>
                </div>

                {advDns?.dnssec?.dnskey_count !== undefined && (
                  <span className="px-2.5 py-1 bg-white border border-slate-200 rounded-md font-mono text-xs text-slate-700 shadow-2xs">
                    DNSKEY Count: <strong>{advDns.dnssec.dnskey_count}</strong>
                  </span>
                )}
              </div>

              {/* DNS Architecture & TTL Heuristics Audit */}
              {dnsAudit && (
                <div className="mt-3 p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-700 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-blue-600" />
                      <span>DNS Architecture &amp; TTL Heuristics Audit</span>
                    </span>
                    {(dnsAudit.fast_flux_suspect || (dnsAudit as any).ttl_analysis?.fast_flux_suspect) && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300 animate-pulse">
                        Fast-Flux Suspect
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    <div className="p-2 bg-white rounded border border-slate-200">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Low TTL / Fast Flux</span>
                      <p className={`font-bold mt-0.5 ${(dnsAudit.low_ttl_detected || (dnsAudit as any).ttl_analysis?.low_ttl_detected) ? 'text-amber-600' : 'text-slate-800'}`}>
                        {(dnsAudit.low_ttl_detected || (dnsAudit as any).ttl_analysis?.low_ttl_detected) ? `Low TTL (${dnsAudit.min_ttl ?? (dnsAudit as any).ttl_analysis?.min_ttl_seconds ?? 30}s)` : `Normal TTL (${dnsAudit.min_ttl ?? (dnsAudit as any).ttl_analysis?.min_ttl_seconds ?? 300}s)`}
                      </p>
                    </div>
                    <div className="p-2 bg-white rounded border border-slate-200">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Wildcard DNS</span>
                      <p className="font-bold text-slate-800 mt-0.5">
                        {(dnsAudit.has_wildcard_dns || (dnsAudit as any).wildcard_dns?.detected) ? `Enabled (${dnsAudit.wildcard_ip || (dnsAudit as any).wildcard_dns?.wildcard_target || 'Active'})` : 'Disabled'}
                      </p>
                    </div>
                    <div className="p-2 bg-white rounded border border-slate-200">
                      <span className="text-[10px] uppercase font-bold text-slate-400">CNAME Chain Depth</span>
                      <p className="font-bold text-slate-800 mt-0.5">{(dnsAudit.cname_chain?.length ?? (advDns?.records?.cname?.length || 0))} Hops</p>
                    </div>
                  </div>
                </div>
              )}

              {/* DS Records Table */}
              {advDns?.dnssec?.ds_records && advDns.dnssec.ds_records.length > 0 && (
                <div className="mt-4 pt-3 border-t border-emerald-200/80 space-y-2">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-900 block">
                    Authoritative DS Delegation Records ({advDns.dnssec.ds_records.length})
                  </span>
                  <div className="border border-emerald-200 rounded-lg overflow-hidden bg-white">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-emerald-50/60 border-b border-emerald-100 text-emerald-900 font-semibold text-[11px]">
                        <tr>
                          <th className="py-2 px-3">Key Tag</th>
                          <th className="py-2 px-3">Algorithm</th>
                          <th className="py-2 px-3">Digest Type</th>
                          <th className="py-2 px-3">Digest</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-emerald-50">
                        {advDns.dnssec.ds_records.map((ds, idx) => {
                          const algoName = ds.algorithm === 13 ? 'ECDSA P-256 (SHA-256)' :
                            ds.algorithm === 8 ? 'RSA/SHA-256' :
                            ds.algorithm === 15 ? 'Ed25519' : `Algorithm ${ds.algorithm}`;
                          const digestTypeName = ds.digest_type === 2 ? 'SHA-256' : ds.digest_type === 1 ? 'SHA-1' : `Type ${ds.digest_type}`;
                          return (
                            <tr key={idx} className="hover:bg-slate-50/60">
                              <td className="py-2 px-3 font-bold text-slate-800">{ds.key_tag}</td>
                              <td className="py-2 px-3 text-slate-600">{algoName}</td>
                              <td className="py-2 px-3 text-slate-500">{digestTypeName}</td>
                              <td className="py-2 px-3 text-slate-700 flex items-center justify-between gap-2">
                                <span className="truncate max-w-sm" title={ds.digest}>{ds.digest}</span>
                                <button
                                  onClick={() => copyToClipboard(ds.digest, `ds_${idx}`)}
                                  className="text-slate-400 hover:text-emerald-700 p-1 cursor-pointer"
                                  title="Copy Digest"
                                >
                                  {copiedKey === `ds_${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>

            {/* Active DNS Resolver Probe (dig) */}
            {((dnsAudit?.active_dig_findings && dnsAudit.active_dig_findings.length > 0) || (domainInfo.active_recon_summary?.dns_findings && domainInfo.active_recon_summary.dns_findings.length > 0)) && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between">
                  <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-blue-600" />
                    <span>Active DNS Resolver Probe (dig)</span>
                  </h5>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-100 text-blue-800 border border-blue-200">
                    Live Verified Records
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {(dnsAudit?.active_dig_findings || domainInfo.active_recon_summary?.dns_findings || []).map((f: string, fIdx: number) => (
                    <span key={fIdx} className="px-2.5 py-1 rounded-lg text-xs font-mono bg-white border border-slate-200 text-slate-800 shadow-2xs">
                      ✓ {f}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Forward-Confirmed Reverse DNS (FCrDNS) Verification */}
            {fcrdns && (
              <div className={`p-4 rounded-xl border ${
                fcrdns.is_fcrdns_valid
                  ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                  : fcrdns.status === 'MISMATCH'
                  ? 'bg-amber-50/70 border-amber-200 text-amber-950'
                  : 'bg-slate-50 border-slate-200 text-slate-800'
              }`}>
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
                      fcrdns.is_fcrdns_valid
                        ? 'bg-emerald-100 border-emerald-300 text-emerald-700'
                        : fcrdns.status === 'MISMATCH'
                        ? 'bg-amber-100 border-amber-300 text-amber-700'
                        : 'bg-slate-200 border-slate-300 text-slate-600'
                    }`}>
                      {fcrdns.is_fcrdns_valid ? <ShieldCheck className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-bold">
                          {fcrdns.is_fcrdns_valid
                            ? 'Forward-Confirmed Reverse DNS (FCrDNS) Validated'
                            : fcrdns.status === 'MISMATCH'
                            ? 'FCrDNS Verification Mismatch / Divergence'
                            : 'FCrDNS: Reverse PTR Record Absent'}
                        </h4>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                          fcrdns.is_fcrdns_valid
                            ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                            : fcrdns.status === 'MISMATCH'
                            ? 'bg-amber-100 text-amber-800 border-amber-300'
                            : 'bg-slate-200 text-slate-700 border-slate-300'
                        }`}>
                          {fcrdns.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 mt-0.5">
                        {fcrdns.details}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Bidirectional Resolution Pipeline Flow */}
                <div className="mt-3 pt-3 border-t border-slate-200/80 grid grid-cols-1 md:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                    <span className="text-[10px] font-sans font-bold text-slate-500 uppercase">1. Queried Target IP</span>
                    <p className="font-bold text-slate-900 truncate" title={fcrdns.ip}>{fcrdns.ip}</p>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                    <span className="text-[10px] font-sans font-bold text-slate-500 uppercase">2. Reverse PTR Host(s)</span>
                    <p className="font-bold text-blue-700 truncate" title={(fcrdns.ptr_hosts || []).join(', ')}>
                      {(fcrdns.ptr_hosts && fcrdns.ptr_hosts.length > 0) ? fcrdns.ptr_hosts.join(', ') : 'No PTR'}
                    </p>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                    <span className="text-[10px] font-sans font-bold text-slate-500 uppercase">3. Forward A/AAAA IPs</span>
                    <p className="font-bold text-indigo-700 truncate" title={(fcrdns.forward_ips || []).join(', ')}>
                      {(fcrdns.forward_ips && fcrdns.forward_ips.length > 0) ? fcrdns.forward_ips.join(', ') : 'No Forward IP'}
                    </p>
                  </div>
                  <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                    <span className="text-[10px] font-sans font-bold text-slate-500 uppercase">4. Verification Result</span>
                    <div className="flex items-center gap-1.5 pt-0.5">
                      {fcrdns.is_fcrdns_valid ? (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                          <span className="text-xs font-bold text-emerald-700">Bidirectional Match</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-4 h-4 text-amber-600" />
                          <span className="text-xs font-bold text-amber-700">Unconfirmed</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 2. DNS Zone Hygiene & Heuristics */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              {/* Wildcard DNS */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Wildcard DNS Record</span>
                <p className={`font-bold ${advDns?.heuristics?.has_wildcard_dns ? 'text-amber-700' : 'text-slate-800'}`}>
                  {advDns?.heuristics?.has_wildcard_dns ? 'Catch-All Active (*)' : 'Disabled / Standard'}
                </p>
                <p className="text-[11px] text-slate-500 font-mono">
                  {advDns?.heuristics?.wildcard_ip ? `Resolves: ${advDns.heuristics.wildcard_ip}` : 'Random hostnames return NXDOMAIN'}
                </p>
              </div>

              {/* TTL Rotation & Fast Flux */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">TTL Rotation / Fast-Flux</span>
                <p className={`font-bold ${advDns?.heuristics?.fast_flux_suspect ? 'text-rose-600' : 'text-slate-800'}`}>
                  {advDns?.heuristics?.fast_flux_suspect ? 'Fast-Flux Suspect' : 'Standard TTL Profile'}
                </p>
                <p className="text-[11px] text-slate-500 font-mono">
                  Min TTL: {advDns?.heuristics?.min_ttl ? `${advDns.heuristics.min_ttl}s` : 'Standard'}
                </p>
              </div>

              {/* Dangling CNAMEs */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Subdomain Takeover Check</span>
                <p className={`font-bold ${advDns?.heuristics?.dangling_cnames?.length ? 'text-rose-600' : 'text-emerald-700'}`}>
                  {advDns?.heuristics?.dangling_cnames?.length ? `${advDns.heuristics.dangling_cnames.length} Vulnerable CNAMEs` : '0 Dangling CNAMEs'}
                </p>
                <p className="text-[11px] text-slate-500">
                  {advDns?.heuristics?.dangling_cnames?.length ? 'Points to unallocated cloud resource' : 'No dangling cloud pointers'}
                </p>
              </div>

              {/* SPF Policy Alignment */}
              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">SPF Validation</span>
                <p className={`font-bold ${advDns?.heuristics?.suspicious_spf ? 'text-amber-700' : 'text-slate-800'}`}>
                  {advDns?.heuristics?.suspicious_spf ? 'Non-Standard SPF' : 'Valid SPF Configured'}
                </p>
                <p className="text-[11px] text-slate-500 truncate" title={advDns?.heuristics?.spf_details || ''}>
                  {advDns?.heuristics?.spf_details ? 'Published in TXT records' : 'No SPF published'}
                </p>
              </div>
            </div>

            {/* 3. DNS Records Filter & Search Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
              <div className="flex items-center gap-2 flex-wrap">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={dnsSearch}
                    onChange={e => setDnsSearch(e.target.value)}
                    placeholder="Search DNS records..."
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-hidden focus:ring-1 focus:ring-blue-500 font-mono w-48"
                  />
                </div>

                <div className="flex items-center gap-1 overflow-x-auto p-1 bg-slate-100 rounded-lg border border-slate-200 text-xs">
                  {['all', 'a', 'mx', 'ns', 'txt', 'soa', 'caa', 'cname', 'https'].map(f => (
                    <button
                      key={f}
                      onClick={() => setDnsFilter(f)}
                      className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer uppercase text-[10px] ${
                        dnsFilter === f ? 'bg-white text-blue-700 shadow-2xs font-bold' : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      {f === 'all' ? 'All Types' : f}
                    </button>
                  ))}
                </div>
              </div>

              <span className="text-xs text-slate-500 font-mono self-center">
                Query target: <strong>{domainInfo.target}</strong>
              </span>
            </div>

            {/* 4. Complete DNS Records Directory */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* A & AAAA (IPv4 & IPv6) */}
              {(dnsFilter === 'all' || dnsFilter === 'a') && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Server className="w-3.5 h-3.5 text-blue-600" />
                      <span>A &amp; AAAA Records (Host IPs)</span>
                    </span>
                    {advDns?.ttls?.a && (
                      <span className="text-[10px] font-mono text-slate-500">TTL: {advDns.ttls.a}s</span>
                    )}
                  </div>
                  <div className="space-y-1.5 font-mono text-xs text-slate-800">
                    {(advDns?.records?.a || dns.a || []).filter(ip => !dnsSearch || ip.toLowerCase().includes(dnsSearch.toLowerCase())).map((ip, i) => (
                      <div key={i} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-blue-100 text-blue-800">A</span>
                          <span className="font-bold text-slate-900">{ip}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => copyToClipboard(ip, `ip_a_${i}`)}
                            className="text-slate-400 hover:text-blue-600 p-1 cursor-pointer"
                            title="Copy IP"
                          >
                            {copiedKey === `ip_a_${i}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                          <InvestigateAssetButton ioc={ip} iocType="ip" compact={true} onNavigateToJob={onNavigateToJob} />
                        </div>
                      </div>
                    ))}
                    {(advDns?.records?.aaaa || dns.aaaa || []).filter(ip6 => !dnsSearch || ip6.toLowerCase().includes(dnsSearch.toLowerCase())).map((ip6, i) => (
                      <div key={i} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-purple-100 text-purple-800">AAAA</span>
                          <span className="font-bold text-slate-900 truncate max-w-[200px]" title={ip6}>{ip6}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => copyToClipboard(ip6, `ip_aaaa_${i}`)}
                            className="text-slate-400 hover:text-purple-600 p-1 cursor-pointer"
                            title="Copy IPv6"
                          >
                            {copiedKey === `ip_aaaa_${i}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                          <InvestigateAssetButton ioc={ip6} iocType="ip" compact={true} onNavigateToJob={onNavigateToJob} />
                        </div>
                      </div>
                    ))}
                    {(!advDns?.records?.a?.length && !dns.a?.length && !advDns?.records?.aaaa?.length && !dns.aaaa?.length) && (
                      <p className="text-slate-400 text-xs py-1">No A or AAAA address records published.</p>
                    )}
                  </div>
                </div>
              )}

              {/* MX Records */}
              {(dnsFilter === 'all' || dnsFilter === 'mx') && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Mail className="w-3.5 h-3.5 text-blue-600" />
                      <span>MX (Mail Exchangers)</span>
                    </span>
                    {advDns?.ttls?.mx && (
                      <span className="text-[10px] font-mono text-slate-500">TTL: {advDns.ttls.mx}s</span>
                    )}
                  </div>
                  <div className="space-y-1.5 font-mono text-xs text-slate-800">
                    {(advDns?.records?.mx || dns.mx || []).map((mxItem, i) => {
                      const host = typeof mxItem === 'object' ? mxItem.host : mxItem;
                      const priority = typeof mxItem === 'object' ? mxItem.priority : 10;
                      if (dnsSearch && !host.toLowerCase().includes(dnsSearch.toLowerCase())) return null;
                      return (
                        <div key={i} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-100 text-amber-800">
                              Prio {priority}
                            </span>
                            <span className="font-bold text-slate-900 truncate max-w-xs" title={host}>{host}</span>
                          </div>
                          <InvestigateAssetButton ioc={host} iocType="domain" compact={true} onNavigateToJob={onNavigateToJob} />
                        </div>
                      );
                    })}
                    {(!advDns?.records?.mx?.length && !dns.mx?.length) && (
                      <p className="text-slate-400 text-xs py-1">No MX records configured.</p>
                    )}
                  </div>
                </div>
              )}

              {/* NS (Authoritative Nameservers) */}
              {(dnsFilter === 'all' || dnsFilter === 'ns') && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-blue-600" />
                      <span>NS (Authoritative Nameservers)</span>
                    </span>
                    {advDns?.ttls?.ns && (
                      <span className="text-[10px] font-mono text-slate-500">TTL: {advDns.ttls.ns}s</span>
                    )}
                  </div>
                  <div className="space-y-1.5 font-mono text-xs text-slate-800">
                    {(advDns?.records?.ns || dns.ns || []).filter(nsHost => !dnsSearch || nsHost.toLowerCase().includes(dnsSearch.toLowerCase())).map((nsHost, i) => (
                      <div key={i} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between">
                        <span className="font-bold text-slate-900 truncate max-w-xs">{nsHost}</span>
                        <InvestigateAssetButton ioc={nsHost} iocType="domain" compact={true} onNavigateToJob={onNavigateToJob} />
                      </div>
                    ))}
                    {(!advDns?.records?.ns?.length && !dns.ns?.length) && (
                      <p className="text-slate-400 text-xs py-1">No NS records returned.</p>
                    )}
                  </div>
                </div>
              )}

              {/* TXT Records */}
              {(dnsFilter === 'all' || dnsFilter === 'txt') && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <FileCode className="w-3.5 h-3.5 text-blue-600" />
                      <span>TXT Records (SPF, Verification &amp; Security)</span>
                    </span>
                    {advDns?.ttls?.txt && (
                      <span className="text-[10px] font-mono text-slate-500">TTL: {advDns.ttls.txt}s</span>
                    )}
                  </div>
                  <div className="space-y-2 font-mono text-xs text-slate-800">
                    {(advDns?.records?.txt || dns.txt || []).filter(txt => !dnsSearch || txt.toLowerCase().includes(dnsSearch.toLowerCase())).map((txt, i) => {
                      const isSpf = txt.toLowerCase().startsWith('v=spf1');
                      const isGoogle = txt.toLowerCase().includes('google-site-verification');
                      const isMs = txt.toLowerCase().includes('ms=');
                      const badgeLabel = isSpf ? 'SPF Policy' : isGoogle ? 'Google Verify' : isMs ? 'Microsoft 365' : 'TXT';
                      const badgeColor = isSpf ? 'bg-emerald-100 text-emerald-800' : isGoogle ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-700';

                      return (
                        <div key={i} className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${badgeColor}`}>
                              {badgeLabel}
                            </span>
                            <button
                              onClick={() => copyToClipboard(txt, `txt_${i}`)}
                              className="text-slate-400 hover:text-blue-600 p-1 cursor-pointer flex items-center gap-1 text-[10px]"
                            >
                              {copiedKey === `txt_${i}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === `txt_${i}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <p className="text-[11px] text-slate-700 break-all select-all font-mono leading-relaxed">
                            {txt}
                          </p>
                        </div>
                      );
                    })}
                    {(!advDns?.records?.txt?.length && !dns.txt?.length) && (
                      <p className="text-slate-400 text-xs py-1">No TXT records found.</p>
                    )}
                  </div>
                </div>
              )}

              {/* SOA Records */}
              {(dnsFilter === 'all' || dnsFilter === 'soa') && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-blue-600" />
                      <span>SOA (Start of Authority)</span>
                    </span>
                    {advDns?.ttls?.soa && (
                      <span className="text-[10px] font-mono text-slate-500">TTL: {advDns.ttls.soa}s</span>
                    )}
                  </div>
                  {advDns?.records?.soa && advDns.records.soa.length > 0 ? (
                    <div className="space-y-2 text-xs font-mono">
                      {advDns.records.soa.map((soa, idx) => (
                        <div key={idx} className="p-3 bg-white rounded-lg border border-slate-200 space-y-1.5 text-slate-800">
                          <p>Primary NS (mname): <strong className="text-blue-700">{soa.mname}</strong></p>
                          <p>Responsible Contact (rname): <span className="text-slate-600">{soa.rname}</span></p>
                          <div className="grid grid-cols-2 gap-2 pt-1 text-[11px] text-slate-500">
                            <span>Serial: <strong>{soa.serial}</strong></span>
                            <span>Refresh: {soa.refresh}s</span>
                            <span>Retry: {soa.retry}s</span>
                            <span>Expire: {soa.expire}s</span>
                            <span>Min TTL: {soa.minimum}s</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-400 text-xs py-1">No SOA record returned.</p>
                  )}
                </div>
              )}

              {/* CAA Records */}
              {(dnsFilter === 'all' || dnsFilter === 'caa') && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-blue-600" />
                    <span>CAA (Certificate Authority Authorization)</span>
                  </span>
                  {advDns?.records?.caa && advDns.records.caa.length > 0 ? (
                    <div className="space-y-1.5 text-xs font-mono">
                      {advDns.records.caa.map((caa, idx) => (
                        <div key={idx} className="p-2 bg-white rounded-lg border border-slate-200 flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-indigo-100 text-indigo-800 uppercase">
                              {caa.tag}
                            </span>
                            <span className="text-slate-900 font-bold">{caa.value}</span>
                          </div>
                          <span className="text-[10px] text-slate-400">Flags: {caa.flags}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-400 text-xs py-1">No CAA restrictions published (Any public CA may issue certificates).</p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ================= TAB: WEB FINGERPRINT ================= */}
        {activeTab === 'web' && (
          <div className="space-y-6">
            {web ? (
              <>
                {/* 1. Connection & Final Destination Banner */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-800 border border-blue-200">
                        HTTP {web.status_code || 200}
                      </span>
                      <span className="text-xs font-bold text-slate-900">
                        {web.final_url || `https://${domainInfo.target}/`}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 font-mono">
                      Initial Request: {web.initial_url || domainInfo.target} • {web.hop_count || 0} Redirect Hop{(web.hop_count || 0) === 1 ? '' : 's'}
                    </p>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Security Grade</span>
                      <span className={`text-xl font-extrabold ${
                        ['A+', 'A'].includes(web.security_headers?.grade || '') ? 'text-emerald-600' :
                        ['B', 'C'].includes(web.security_headers?.grade || '') ? 'text-amber-600' : 'text-rose-600'
                      }`}>
                        {web.security_headers?.grade || 'F'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Security Headers Audit & Server Disclosure */}
                {webExposureAudit && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                    <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-blue-600" />
                      <span>Security Headers Audit &amp; Server Disclosure</span>
                    </h5>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                        <span className="text-[10px] uppercase font-bold text-slate-400">Server Banner</span>
                        <p className="font-mono text-slate-800 font-semibold mt-0.5">
                          {webExposureAudit.server_banner || 'Hidden / Redacted'}
                        </p>
                      </div>
                      <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                        <span className="text-[10px] uppercase font-bold text-slate-400">Missing Critical Headers</span>
                        <p className="font-medium text-rose-600 mt-0.5">
                          {((webExposureAudit.missing_security_headers || (webExposureAudit as any).missing_headers || []).length > 0)
                            ? (webExposureAudit.missing_security_headers || (webExposureAudit as any).missing_headers || []).join(', ')
                            : 'All standard security headers configured'}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Active HTTP Headers & Probe (curl) */}
                {((webExposureAudit?.active_curl_findings && webExposureAudit.active_curl_findings.length > 0) || (domainInfo.active_recon_summary?.http_findings && domainInfo.active_recon_summary.http_findings.length > 0)) && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                    <div className="flex items-center justify-between">
                      <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Active HTTP Probe &amp; Security Header Extraction (curl)</span>
                      </h5>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                        Live Verified
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {(webExposureAudit?.active_curl_findings || domainInfo.active_recon_summary?.http_findings || []).map((f: string, fIdx: number) => (
                        <span key={fIdx} className="px-2.5 py-1 rounded-lg text-xs font-mono bg-white border border-slate-200 text-slate-800 shadow-2xs">
                          ✓ {f}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* 2. Visual Step-by-Step Redirect Chain */}
                {web.redirect_chain && web.redirect_chain.length > 0 && (
                  <div className="space-y-2">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <CornerDownRight className="w-3.5 h-3.5 text-blue-600" />
                      <span>HTTP Redirection Chain ({web.redirect_chain.length} Hops)</span>
                    </h5>
                    <div className="border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-100 bg-white">
                      {web.redirect_chain.map((hop, hidx) => (
                        <div key={hidx} className="p-3 flex items-center justify-between text-xs font-mono gap-3 hover:bg-slate-50/50">
                          <div className="flex items-center gap-2.5 truncate">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 shrink-0">
                              Hop {hop.hop ?? hidx + 1}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                              String(hop.status_code).startsWith('3') ? 'bg-amber-100 text-amber-800' : 'bg-emerald-100 text-emerald-800'
                            }`}>
                              {hop.status_code}
                            </span>
                            <span className="truncate text-slate-800 font-medium" title={hop.url}>{hop.url}</span>
                          </div>
                          {hop.location && (
                            <div className="flex items-center gap-1 text-slate-500 text-[11px] shrink-0 truncate max-w-xs" title={hop.location}>
                              <ArrowRight className="w-3 h-3 text-blue-600" />
                              <span className="truncate">{hop.location}</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 3. Security Headers Compliance Matrix */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                      <span>Security Headers Audit</span>
                    </h5>
                    <span className="text-xs text-slate-400 font-mono">Score: {web.security_headers?.score ?? 0}/100</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {[
                      { name: 'Strict-Transport-Security', key: 'hsts', obj: web.security_headers?.hsts, desc: 'Enforces encrypted HTTPS connections.' },
                      { name: 'Content-Security-Policy', key: 'csp', obj: web.security_headers?.csp, desc: 'Mitigates Cross-Site Scripting (XSS) and data injection.' },
                      { name: 'X-Frame-Options', key: 'x_frame_options', obj: web.security_headers?.x_frame_options, desc: 'Prevents clickjacking frame overlays.' },
                      { name: 'X-Content-Type-Options', key: 'x_content_type_options', obj: web.security_headers?.x_content_type_options, desc: 'Prevents MIME sniffing attacks.' },
                      { name: 'Referrer-Policy', key: 'referrer_policy', obj: web.security_headers?.referrer_policy, desc: 'Governs URL referrer leakage to third-parties.' },
                      { name: 'Permissions-Policy', key: 'permissions_policy', obj: web.security_headers?.permissions_policy, desc: 'Restricts sensitive device and browser APIs.' }
                    ].map((hdr, idx) => {
                      const isPresent = Boolean(hdr.obj?.present);
                      const val = hdr.obj?.value;
                      return (
                        <div key={idx} className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5 flex flex-col justify-between">
                          <div>
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-bold text-slate-800 truncate" title={hdr.name}>{hdr.name}</span>
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                                isPresent ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                              }`}>
                                {isPresent ? 'Configured' : 'Missing'}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-500 leading-snug">{hdr.desc}</p>
                          </div>

                          {val ? (
                            <div className="pt-2 border-t border-slate-200">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-slate-400 font-mono truncate max-w-[170px]" title={val}>{val}</span>
                                <button
                                  onClick={() => copyToClipboard(val, `hdr_${idx}`)}
                                  className="text-slate-400 hover:text-blue-600 p-0.5 cursor-pointer"
                                  title="Copy Header"
                                >
                                  {copiedKey === `hdr_${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                                </button>
                              </div>
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* 4. Favicon Fingerprint & Shodan Threat Recon */}
                {web.favicon && (
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                    <div className="flex items-center justify-between">
                      <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                        <Flame className="w-4 h-4 text-amber-600" />
                        <span>Favicon MurmurHash3 &amp; Shodan Recon</span>
                      </h5>
                      {web.favicon.murmur_hash !== null && web.favicon.murmur_hash !== undefined && (
                        <a
                          href={`https://www.shodan.io/search?query=http.favicon.hash%3A${web.favicon.murmur_hash}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-semibold shadow-2xs transition-colors"
                        >
                          <span>Query on Shodan</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                      <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[10px] text-slate-400 uppercase tracking-wider block">MurmurHash3 (MMH3)</span>
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-blue-700">{web.favicon.murmur_hash ?? 'Not computed'}</span>
                          {web.favicon.murmur_hash && (
                            <button
                              onClick={() => copyToClipboard(String(web.favicon?.murmur_hash), 'fav_mmh3')}
                              className="text-slate-400 hover:text-blue-600 p-0.5 cursor-pointer"
                            >
                              {copiedKey === 'fav_mmh3' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            </button>
                          )}
                        </div>
                      </div>

                      <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Favicon MD5</span>
                        <span className="font-bold text-slate-800 truncate block" title={web.favicon.md5 || ''}>
                          {web.favicon.md5 || 'N/A'}
                        </span>
                      </div>

                      <div className="p-2.5 bg-white rounded-lg border border-slate-200 space-y-0.5">
                        <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Favicon Source URL</span>
                        <span className="text-slate-600 truncate block" title={web.favicon.url || ''}>
                          {web.favicon.url || 'Default icon root'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* 5. Detected Technologies & DOM Architecture */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                  <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <Code className="w-4 h-4 text-blue-600" />
                    <span>Detected Web Stack &amp; DOM Insights</span>
                  </h5>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Server Banner</span>
                      <p className="font-bold font-mono text-slate-900 truncate">
                        {web.server_technology || web.response_headers?.server || 'Hidden / Generic'}
                      </p>
                    </div>

                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Powered-By Header</span>
                      <p className="font-bold font-mono text-slate-900 truncate">
                        {web.powered_by || 'Not advertised'}
                      </p>
                    </div>

                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">Page Title</span>
                      <p className="font-medium text-slate-800 truncate" title={web.dom_analysis?.title || 'None'}>
                        {web.dom_analysis?.title || 'No HTML Title Tag'}
                      </p>
                    </div>

                    <div className="p-3 bg-white border border-slate-200 rounded-lg space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">DOM Elements</span>
                      <p className="font-mono text-slate-700 text-[11px]">
                        Scripts: {web.dom_analysis?.external_scripts?.length ?? 0} • Forms: {web.dom_analysis?.has_login_form ? 'Login Form Present' : 'Standard Forms'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* 6. Raw HTTP Response Headers Inspector */}
                {web.response_headers && Object.keys(web.response_headers).length > 0 && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-blue-600" />
                        <span>Raw HTTP Response Headers ({Object.keys(web.response_headers).length})</span>
                      </h5>
                      <input
                        type="text"
                        value={headerSearch}
                        onChange={e => setHeaderSearch(e.target.value)}
                        placeholder="Filter headers..."
                        className="px-2.5 py-1 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-hidden font-mono w-44"
                      />
                    </div>

                    <div className="border border-slate-200 rounded-xl overflow-hidden max-h-72 overflow-y-auto bg-white">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px] sticky top-0">
                          <tr>
                            <th className="py-2 px-3 w-1/3">Header Name</th>
                            <th className="py-2 px-3">Value</th>
                            <th className="py-2 px-2 text-right w-12">Copy</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {Object.entries(web.response_headers)
                            .filter(([k, v]) => !headerSearch || k.toLowerCase().includes(headerSearch.toLowerCase()) || v.toLowerCase().includes(headerSearch.toLowerCase()))
                            .map(([k, v], idx) => (
                              <tr key={idx} className="hover:bg-slate-50/50">
                                <td className="py-1.5 px-3 font-bold text-slate-800 truncate max-w-xs">{k}</td>
                                <td className="py-1.5 px-3 text-slate-600 break-all select-all">{v}</td>
                                <td className="py-1.5 px-2 text-right">
                                  <button
                                    onClick={() => copyToClipboard(`${k}: ${v}`, `raw_hdr_${idx}`)}
                                    className="text-slate-400 hover:text-blue-600 p-1 cursor-pointer"
                                    title="Copy header pair"
                                  >
                                    {copiedKey === `raw_hdr_${idx}` ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                                  </button>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                No web fingerprint captured for this asset.
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: THREAT FEEDS (CTI) ================= */}
        {activeTab === 'cti' && (
          <div className="space-y-6">
            {cti ? (
              <>
                {/* 1. Global Threat Verdict Hero Card */}
                <div className={`p-5 rounded-2xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
                  cti.overall_verdict === 'malicious'
                    ? 'bg-rose-50 border-rose-200 text-rose-950'
                    : cti.overall_verdict === 'suspicious'
                    ? 'bg-amber-50 border-amber-200 text-amber-950'
                    : 'bg-emerald-50 border-emerald-200 text-emerald-950'
                }`}>
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2">
                      {cti.overall_verdict === 'malicious' ? (
                        <ShieldAlert className="w-6 h-6 text-rose-600 shrink-0" />
                      ) : cti.overall_verdict === 'suspicious' ? (
                        <AlertTriangle className="w-6 h-6 text-amber-600 shrink-0" />
                      ) : (
                        <ShieldCheck className="w-6 h-6 text-emerald-600 shrink-0" />
                      )}
                      <h4 className="text-base font-extrabold capitalize">
                        Consensus Verdict: {cti.overall_verdict}
                      </h4>
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider border ${
                        cti.overall_verdict === 'malicious'
                          ? 'bg-rose-100 text-rose-800 border-rose-300'
                          : cti.overall_verdict === 'suspicious'
                          ? 'bg-amber-100 text-amber-800 border-amber-300'
                          : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                      }`}>
                        {cti.malicious_votes ?? 0} Flag{(cti.malicious_votes ?? 0) === 1 ? '' : 's'} Detected
                      </span>
                    </div>

                    <p className="text-xs leading-relaxed opacity-90">
                      Cross-referenced against VirusTotal, URLhaus (abuse.ch), ThreatFox (abuse.ch), AbuseIPDB, and AlienVault OTX feeds.
                    </p>

                    {/* Threat Tags Cloud */}
                    {cti.threat_tags && cti.threat_tags.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {cti.threat_tags.map((tag, tidx) => (
                          <span key={tidx} className="px-2 py-0.5 rounded-md text-[10px] font-bold font-mono bg-rose-200/80 text-rose-900">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="text-right shrink-0">
                    <span className="text-3xl font-black">{cti.malicious_votes ?? 0}</span>
                    <span className="text-xs font-semibold"> / {cti.total_feeds_queried ?? 5} Feeds</span>
                  </div>
                </div>

                {/* 2. Multi-Engine Threat Intelligence Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {/* VirusTotal */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-slate-800">VirusTotal</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          cti.feeds?.virustotal?.detections && cti.feeds.virustotal.detections > 0
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {cti.feeds?.virustotal?.verdict || 'Clean'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        Detections: {cti.feeds?.virustotal?.detections ?? 0} engines
                      </p>
                    </div>
                    <div className="pt-2 border-t border-slate-200">
                      <a
                        href={`https://www.virustotal.com/gui/search/${encodeURIComponent(domainInfo.target)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px] font-medium"
                      >
                        <span>VirusTotal Report</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>

                  {/* URLhaus (abuse.ch) */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-slate-800">URLhaus (abuse.ch)</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          cti.feeds?.urlhaus?.url_count && cti.feeds.urlhaus.url_count > 0
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {cti.feeds?.urlhaus?.verdict || 'Clean'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        Active Malware URLs: {cti.feeds?.urlhaus?.url_count ?? 0}
                      </p>
                    </div>
                    <div className="pt-2 border-t border-slate-200">
                      <a
                        href={`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domainInfo.target)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px] font-medium"
                      >
                        <span>URLhaus Search</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>

                  {/* ThreatFox (abuse.ch) */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-slate-800">ThreatFox (abuse.ch)</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          cti.feeds?.threatfox?.ioc_count && cti.feeds.threatfox.ioc_count > 0
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {cti.feeds?.threatfox?.verdict || 'Clean'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        IOC Matches: {cti.feeds?.threatfox?.ioc_count ?? 0}
                      </p>
                    </div>
                    <div className="pt-2 border-t border-slate-200">
                      <a
                        href={`https://threatfox.abuse.ch/browse.php?search=${encodeURIComponent(domainInfo.target)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px] font-medium"
                      >
                        <span>ThreatFox Database</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>

                  {/* AbuseIPDB */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-slate-800">AbuseIPDB</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          (cti.feeds?.abuseipdb?.abuse_confidence_score ?? 0) > 25
                            ? 'bg-rose-100 text-rose-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {cti.feeds?.abuseipdb?.verdict || 'Clean'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        Abuse Score: {cti.feeds?.abuseipdb?.abuse_confidence_score ?? 0}% ({cti.feeds?.abuseipdb?.total_reports ?? 0} reports)
                      </p>
                    </div>
                    <div className="pt-2 border-t border-slate-200">
                      <a
                        href={`https://www.abuseipdb.com/check/${encodeURIComponent(domainInfo.target)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px] font-medium"
                      >
                        <span>AbuseIPDB Check</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>

                  {/* AlienVault OTX */}
                  <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-2 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-slate-800">AlienVault OTX</span>
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          (cti.feeds?.alienvault_otx?.pulse_count ?? 0) > 0
                            ? 'bg-amber-100 text-amber-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {(cti.feeds?.alienvault_otx?.pulse_count ?? 0) > 0 ? 'Pulses Found' : 'Clean'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-mono">
                        Threat Pulses: {cti.feeds?.alienvault_otx?.pulse_count ?? 0}
                      </p>
                    </div>
                    <div className="pt-2 border-t border-slate-200">
                      <a
                        href={`https://otx.alienvault.com/indicator/${domainInfo.is_ip ? 'ip' : 'domain'}/${encodeURIComponent(domainInfo.target)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 text-[11px] font-medium"
                      >
                        <span>OTX Community Pulses</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                </div>

                {/* 3. External CTI Quick Pivots */}
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                  <h5 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                    <ExternalLink className="w-4 h-4 text-blue-600" />
                    <span>External Threat Intelligence &amp; Recon Pivots</span>
                  </h5>
                  <div className="flex flex-wrap gap-2">
                    <a
                      href={`https://www.virustotal.com/gui/search/${encodeURIComponent(domainInfo.target)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-medium text-slate-800 inline-flex items-center gap-1.5 shadow-2xs"
                    >
                      <span>VirusTotal</span>
                      <ExternalLink className="w-3 h-3 text-slate-400" />
                    </a>
                    <a
                      href={`https://otx.alienvault.com/indicator/${domainInfo.is_ip ? 'ip' : 'domain'}/${encodeURIComponent(domainInfo.target)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-medium text-slate-800 inline-flex items-center gap-1.5 shadow-2xs"
                    >
                      <span>AlienVault OTX</span>
                      <ExternalLink className="w-3 h-3 text-slate-400" />
                    </a>
                    <a
                      href={`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domainInfo.target)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-medium text-slate-800 inline-flex items-center gap-1.5 shadow-2xs"
                    >
                      <span>URLhaus</span>
                      <ExternalLink className="w-3 h-3 text-slate-400" />
                    </a>
                    <a
                      href={`https://www.shodan.io/search?query=${encodeURIComponent(domainInfo.target)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-medium text-slate-800 inline-flex items-center gap-1.5 shadow-2xs"
                    >
                      <span>Shodan</span>
                      <ExternalLink className="w-3 h-3 text-slate-400" />
                    </a>
                    <a
                      href={`https://search.censys.io/hosts?q=${encodeURIComponent(domainInfo.target)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-white hover:bg-slate-100 border border-slate-200 rounded-lg text-xs font-medium text-slate-800 inline-flex items-center gap-1.5 shadow-2xs"
                    >
                      <span>Censys Search</span>
                      <ExternalLink className="w-3 h-3 text-slate-400" />
                    </a>
                  </div>
                </div>
              </>
            ) : (
              <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                No threat feeds queried for this asset.
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: PASSIVE WEB EXPOSURE & ASSET HARVESTING ================= */}
        {activeTab === 'exposure' && (
          <div className="space-y-6">
            {/* Header Banner */}
            <div className="p-4 bg-gradient-to-r from-amber-50/70 via-slate-50 to-white border border-amber-200 rounded-xl space-y-3">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-amber-600" />
                    <span>Passive Web Exposure &amp; Disclosed Assets</span>
                  </h4>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Harvester for robots.txt rules, sitemap.xml endpoints, and RFC 9116 /.well-known/ declarations, isolating sensitive admin routes and API configurations.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                    webExposure?.has_exposure_data
                      ? 'bg-amber-100 text-amber-800 border-amber-300'
                      : 'bg-slate-100 text-slate-700 border-slate-200'
                  }`}>
                    {webExposure?.has_exposure_data ? 'Exposure Data Discovered' : 'No Public Disclosure'}
                  </span>
                </div>
              </div>

              {/* Quick Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-xs">
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">robots.txt</span>
                  <p className={`font-bold mt-0.5 ${webExposure?.robots_txt?.present ? 'text-amber-700' : 'text-slate-500'}`}>
                    {webExposure?.robots_txt?.present ? `${webExposure.robots_txt.disallowed_count} Disallow Rules` : 'Absent'}
                  </p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">sitemap.xml</span>
                  <p className={`font-bold mt-0.5 ${webExposure?.sitemap_xml?.present ? 'text-blue-700' : 'text-slate-500'}`}>
                    {webExposure?.sitemap_xml?.present ? `${webExposure.sitemap_xml.total_urls_found} URLs Indexed` : 'Absent'}
                  </p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">security.txt (RFC 9116)</span>
                  <p className={`font-bold mt-0.5 ${webExposure?.well_known?.security_txt?.present ? 'text-emerald-700' : 'text-slate-500'}`}>
                    {webExposure?.well_known?.security_txt?.present ? 'Published' : 'Not Disclosed'}
                  </p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">OpenID / App Links</span>
                  <p className={`font-bold mt-0.5 ${
                    webExposure?.well_known?.openid_configuration?.present || webExposure?.well_known?.assetlinks_json?.present || webExposure?.well_known?.apple_app_site_association?.present
                      ? 'text-purple-700'
                      : 'text-slate-500'
                  }`}>
                    {webExposure?.well_known?.openid_configuration?.present ? 'OIDC Active' :
                     webExposure?.well_known?.assetlinks_json?.present ? 'Mobile Association' : 'None'}
                  </p>
                </div>
              </div>
            </div>

            {/* Exposure Filter Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-slate-50 border border-slate-200 rounded-xl">
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
                <button
                  onClick={() => setExposureCategoryFilter('all')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                    exposureCategoryFilter === 'all'
                      ? 'bg-amber-600 text-white shadow-2xs'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  All Disclosures
                </button>
                <button
                  onClick={() => setExposureCategoryFilter('admin')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                    exposureCategoryFilter === 'admin'
                      ? 'bg-amber-600 text-white shadow-2xs'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  Admin &amp; Sensitive
                </button>
                <button
                  onClick={() => setExposureCategoryFilter('api')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                    exposureCategoryFilter === 'api'
                      ? 'bg-amber-600 text-white shadow-2xs'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  API &amp; Config
                </button>
              </div>

              <div className="relative min-w-[200px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter exposed paths..."
                  value={exposureSearch}
                  onChange={(e) => setExposureSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-hidden focus:border-amber-500"
                />
              </div>
            </div>

            {/* Risk Flags & Findings */}
            {webExposure?.risk_flags && webExposure.risk_flags.length > 0 && (
              <div className="p-4 bg-rose-50/80 border border-rose-200 rounded-xl space-y-2">
                <h5 className="text-xs font-bold text-rose-900 uppercase tracking-wider flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-600" />
                  <span>Sensitive Route Disclosures &amp; Risk Flags ({webExposure.risk_flags.length})</span>
                </h5>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                  {webExposure.risk_flags.map((flag, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-lg border border-rose-200 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-rose-950">{flag.title}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-bold uppercase bg-rose-100 text-rose-800">
                          {flag.severity}
                        </span>
                      </div>
                      <p className="text-slate-600 text-[11px]">{flag.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* robots.txt Explorer */}
            {webExposure?.robots_txt?.present && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-slate-700" />
                    <h5 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      robots.txt Crawler Directives &amp; Disallow Rules
                    </h5>
                  </div>
                  {webExposure.robots_txt.url && (
                    <a
                      href={webExposure.robots_txt.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-600 hover:text-blue-800 inline-flex items-center gap-1 font-mono"
                    >
                      <span>{webExposure.robots_txt.url}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>

                {/* Flagged Sensitive Paths in robots.txt */}
                {webExposure.robots_txt.sensitive_paths_flagged && webExposure.robots_txt.sensitive_paths_flagged.length > 0 && (
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg space-y-1.5">
                    <span className="text-[11px] font-bold text-amber-900 uppercase tracking-wider block">
                      Sensitive Admin &amp; Internal Paths Flagged ({webExposure.robots_txt.sensitive_paths_flagged.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {webExposure.robots_txt.sensitive_paths_flagged
                        .filter(sens => {
                          if (exposureCategoryFilter === 'admin') return sens.category.includes('admin') || sens.category.includes('sensitive');
                          if (exposureCategoryFilter === 'api') return sens.category.includes('api') || sens.category.includes('config');
                          return true;
                        })
                        .filter(sens => !exposureSearch || sens.path.toLowerCase().includes(exposureSearch.toLowerCase()))
                        .map((sens, sIdx) => (
                          <div key={sIdx} className="px-2 py-1 bg-white border border-amber-300 rounded text-xs font-mono flex items-center gap-2">
                            <span className="font-bold text-amber-950">{sens.path}</span>
                            <span className="px-1 py-0.2 bg-amber-100 text-amber-800 text-[10px] rounded uppercase font-semibold">
                              {sens.category}
                            </span>
                          </div>
                        ))}
                    </div>
                  </div>
                )}

                {/* Disallow Paths Grid */}
                <div className="space-y-1.5">
                  <span className="text-[11px] font-semibold text-slate-600">Disallow Rules ({webExposure.robots_txt.disallow_paths.length}):</span>
                  <div className="max-h-48 overflow-y-auto border border-slate-200 rounded-lg bg-white p-2.5 font-mono text-xs text-slate-800 space-y-1">
                    {webExposure.robots_txt.disallow_paths
                      .filter(p => !exposureSearch || p.toLowerCase().includes(exposureSearch.toLowerCase()))
                      .map((p, pIdx) => (
                        <div key={pIdx} className="truncate">Disallow: <span className="text-amber-800">{p}</span></div>
                      ))}
                  </div>
                </div>

                {/* Sitemaps Declared in robots.txt */}
                {webExposure.robots_txt.sitemaps_declared && webExposure.robots_txt.sitemaps_declared.length > 0 && (
                  <div className="text-xs pt-1">
                    <span className="font-semibold text-slate-700">Declared Sitemaps: </span>
                    {webExposure.robots_txt.sitemaps_declared.map((sm, smIdx) => (
                      <a
                        key={smIdx}
                        href={sm}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline font-mono ml-2 inline-flex items-center gap-1"
                      >
                        {sm} <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* sitemap.xml Explorer */}
            {webExposure?.sitemap_xml?.present && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-blue-600" />
                    <h5 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      sitemap.xml Indexed Endpoints ({webExposure.sitemap_xml.total_urls_found})
                    </h5>
                  </div>
                  {webExposure.sitemap_xml.url && (
                    <a
                      href={webExposure.sitemap_xml.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-600 hover:text-blue-800 inline-flex items-center gap-1 font-mono"
                    >
                      <span>{webExposure.sitemap_xml.url}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>

                {/* Sample URLs */}
                {webExposure.sitemap_xml.sample_urls && webExposure.sitemap_xml.sample_urls.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[11px] font-semibold text-slate-600">Sample Discovered URLs:</span>
                    <div className="max-h-40 overflow-y-auto border border-slate-200 rounded-lg bg-white p-2.5 font-mono text-xs text-slate-800 space-y-1">
                      {webExposure.sitemap_xml.sample_urls
                        .filter(u => !exposureSearch || u.toLowerCase().includes(exposureSearch.toLowerCase()))
                        .map((u, uIdx) => (
                          <div key={uIdx} className="truncate text-slate-700 hover:text-blue-600">
                            {u}
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* /.well-known/ Standards Explorer */}
            {webExposure?.well_known && (
              <div className="space-y-3">
                <h5 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-600" />
                  <span>RFC 9116 &amp; /.well-known/ Disclosed Configurations</span>
                </h5>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {/* security.txt */}
                  <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs text-slate-900">RFC 9116 security.txt</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        webExposure.well_known.security_txt?.present
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-100 text-slate-600'
                      }`}>
                        {webExposure.well_known.security_txt?.present ? 'Published' : 'Absent'}
                      </span>
                    </div>
                    {webExposure.well_known.security_txt?.present && (
                      <div className="space-y-1.5 pt-1 text-xs">
                        {webExposure.well_known.security_txt.contacts && webExposure.well_known.security_txt.contacts.length > 0 && (
                          <div className="text-[11px] font-mono text-slate-700">
                            <strong>Security Contact:</strong> {webExposure.well_known.security_txt.contacts.join(', ')}
                          </div>
                        )}
                        {webExposure.well_known.security_txt.fields && Object.keys(webExposure.well_known.security_txt.fields).length > 0 && (
                          <div className="space-y-1 pt-1 font-mono text-[11px] text-slate-600">
                            {Object.entries(webExposure.well_known.security_txt.fields).map(([k, v]) => (
                              <div key={k} className="truncate">
                                <span className="text-slate-500 uppercase">{k}:</span> {v}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* OpenID & Mobile Links */}
                  <div className="p-4 bg-white border border-slate-200 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-xs text-slate-900">OpenID Connect &amp; App Associations</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        webExposure.well_known.openid_configuration?.present || webExposure.well_known.assetlinks_json?.present
                          ? 'bg-purple-100 text-purple-800'
                          : 'bg-slate-100 text-slate-600'
                      }`}>
                        {webExposure.well_known.openid_configuration?.present ? 'OIDC Configured' : 'No Public OIDC'}
                      </span>
                    </div>
                    <div className="space-y-1 text-xs">
                      {webExposure.well_known.openid_configuration?.issuer && (
                        <p className="font-mono text-[11px] text-slate-700 truncate">
                          <strong>Issuer:</strong> {webExposure.well_known.openid_configuration.issuer}
                        </p>
                      )}
                      {webExposure.well_known.assetlinks_json?.package_names && webExposure.well_known.assetlinks_json.package_names.length > 0 && (
                        <p className="font-mono text-[11px] text-slate-700 truncate">
                          <strong>Android Packages:</strong> {webExposure.well_known.assetlinks_json.package_names.join(', ')}
                        </p>
                      )}
                      {webExposure.well_known.apple_app_site_association?.app_ids && webExposure.well_known.apple_app_site_association.app_ids.length > 0 && (
                        <p className="font-mono text-[11px] text-slate-700 truncate">
                          <strong>Apple App IDs:</strong> {webExposure.well_known.apple_app_site_association.app_ids.join(', ')}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: TECHNOLOGY VERSION TO CISA KEV & EPSS VULNERABILITIES ================= */}
        {activeTab === 'vulnerabilities' && (
          <div className="space-y-6">
            {/* Header Banner */}
            <div className={`p-4 rounded-xl border ${
              vulnIntel?.has_critical_kev
                ? 'bg-rose-50/80 border-rose-300 text-rose-950'
                : vulnIntel?.total_vulnerabilities && vulnIntel.total_vulnerabilities > 0
                ? 'bg-amber-50/80 border-amber-200 text-amber-950'
                : 'bg-slate-50 border-slate-200 text-slate-800'
            }`}>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <h4 className="text-sm font-bold flex items-center gap-2">
                    <Bug className="w-4 h-4 text-rose-600" />
                    <span>Technology Version Vulnerability &amp; Exploit Intelligence</span>
                  </h4>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Correlates fingerprinted web servers, frameworks, and CMS versions against CISA Known Exploited Vulnerabilities (KEV) and FIRST EPSS (Exploit Prediction Scoring System).
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {vulnIntel?.has_critical_kev && (
                    <span className="px-3 py-1 rounded-full text-xs font-extrabold bg-rose-600 text-white border border-rose-700 animate-pulse">
                      CISA KEV Actively Exploited In Wild
                    </span>
                  )}
                </div>
              </div>

              {/* Summary Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 text-xs">
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Identified CVEs</span>
                  <p className="text-base font-extrabold text-slate-900 mt-0.5">{vulnIntel?.total_vulnerabilities || 0}</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">CISA KEV Matches</span>
                  <p className={`text-base font-extrabold mt-0.5 ${vulnIntel?.cisa_kev_count ? 'text-rose-600' : 'text-slate-900'}`}>
                    {vulnIntel?.cisa_kev_count || 0}
                  </p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Max EPSS Probability</span>
                  <p className="text-base font-extrabold text-amber-600 mt-0.5">
                    {vulnIntel?.max_epss_score ? `${(vulnIntel.max_epss_score * 100).toFixed(1)}%` : '0%'}
                  </p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Detection Mode</span>
                  <p className="text-xs font-bold text-indigo-700 mt-1">Non-Intrusive Fingerprint</p>
                </div>
              </div>
            </div>

            {/* Findings List */}
            {vulnIntel?.findings && vulnIntel.findings.length > 0 ? (
              <div className="space-y-3">
                <h5 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Discovered Vulnerabilities &amp; Exploitation Likelihood ({vulnIntel.findings.length})
                </h5>

                <div className="space-y-3">
                  {vulnIntel.findings.map((vuln, idx) => (
                    <div key={idx} className="p-4 bg-white border border-slate-200 rounded-xl space-y-3 shadow-2xs hover:border-slate-300 transition-colors">
                      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <span className="text-xs font-mono font-bold text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200">
                            {vuln.cve}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            vuln.severity.toLowerCase() === 'critical' ? 'bg-rose-100 text-rose-800 border border-rose-300' :
                            vuln.severity.toLowerCase() === 'high' ? 'bg-amber-100 text-amber-800 border border-amber-300' :
                            'bg-slate-100 text-slate-700'
                          }`}>
                            {vuln.severity} (CVSS {vuln.cvss})
                          </span>
                          {vuln.cisa_kev && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase bg-rose-600 text-white shadow-2xs">
                              CISA KEV
                            </span>
                          )}
                          <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                            vuln.confidence === 'CONFIRMED_VULNERABLE'
                              ? 'bg-emerald-100 text-emerald-800'
                              : 'bg-slate-100 text-slate-600'
                          }`}>
                            {vuln.confidence === 'CONFIRMED_VULNERABLE' ? 'Confirmed Version Match' : 'Potential Version Exposure'}
                          </span>
                        </div>

                        <div className="flex items-center gap-3 text-xs font-mono">
                          <span className="text-slate-600">
                            EPSS: <strong className="text-amber-700">{(vuln.epss * 100).toFixed(1)}%</strong> ({vuln.epss_percentile}th %ile)
                          </span>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-800 inline-flex items-center gap-1 font-sans text-xs"
                          >
                            <span>NVD</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      </div>

                      <div>
                        <h6 className="text-xs font-bold text-slate-900">{vuln.title}</h6>
                        <p className="text-xs text-slate-600 mt-1 leading-relaxed">{vuln.description}</p>
                      </div>

                      <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200/80 text-xs space-y-1">
                        <div className="flex items-center justify-between text-[11px] text-slate-500">
                          <span>Component: <strong className="text-slate-800 font-mono">{vuln.product}</strong> ({vuln.detected_version})</span>
                          {vuln.cisa_due_date && (
                            <span className="text-rose-700 font-bold">CISA Action Due: {vuln.cisa_due_date}</span>
                          )}
                        </div>
                        <p className="text-slate-700 text-[11px]">
                          <strong>Remediation:</strong> {vuln.remediation}
                        </p>
                      </div>

                      {vuln.disclaimer && (
                        <p className="text-[10px] text-slate-400 italic">
                          *{vuln.disclaimer}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                <p className="font-semibold text-slate-800">No Known Vulnerabilities Correlated</p>
                <p className="text-slate-400 mt-0.5">Fingerprinted server and technology versions did not match active CISA KEV or high-EPSS vulnerability records.</p>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB: BRAND DEFENSE & LOOKALIKE DOMAIN GENERATOR ================= */}
        {activeTab === 'typosquatting' && (
          <div className="space-y-6">
            {/* Header Banner */}
            <div className={`p-4 rounded-xl border ${
              typosquat?.has_live_impersonators
                ? 'bg-rose-50/80 border-rose-300 text-rose-950'
                : 'bg-slate-50 border-slate-200 text-slate-800'
            }`}>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <h4 className="text-sm font-bold flex items-center gap-2">
                    <Crosshair className="w-4 h-4 text-purple-600" />
                    <span>Typosquatting, Homoglyph &amp; Lookalike Domain Intelligence</span>
                  </h4>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Synthesizes potential phishing lookalikes via bitsquatting, homoglyphs, omission, repetition, and TLD swaps, performing live DNS resolution to isolate weaponized impersonators.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${
                    typosquat?.has_live_impersonators
                      ? 'bg-rose-100 text-rose-800 border-rose-300'
                      : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                  }`}>
                    {typosquat?.active_registered_count || 0} Registered Threats
                  </span>
                </div>
              </div>

              {/* Quick Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 text-xs">
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Permutations Generated</span>
                  <p className="text-base font-extrabold text-slate-900 mt-0.5">{typosquat?.total_generated || 0}</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Live Resolving IPs</span>
                  <p className={`text-base font-extrabold mt-0.5 ${typosquat?.active_registered_count ? 'text-rose-600' : 'text-slate-900'}`}>
                    {typosquat?.active_registered_count || 0}
                  </p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Homoglyph / Punycode</span>
                  <p className="text-xs font-bold text-purple-700 mt-1">Unicode Confusable Analysis</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-500 uppercase">Investigation Pivot</span>
                  <p className="text-xs font-bold text-indigo-700 mt-1">One-Click Triage</p>
                </div>
              </div>
            </div>

            {/* Filter Bar */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-slate-50 border border-slate-200 rounded-xl">
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
                <button
                  onClick={() => setTypoFilter('all')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                    typoFilter === 'all'
                      ? 'bg-purple-600 text-white shadow-2xs'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  All ({typosquat?.lookalikes?.length || 0})
                </button>
                <button
                  onClick={() => setTypoFilter('resolving')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                    typoFilter === 'resolving'
                      ? 'bg-rose-600 text-white shadow-2xs'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  Live Resolving Threats ({typosquat?.lookalikes?.filter(l => l.resolves).length || 0})
                </button>
                <button
                  onClick={() => setTypoFilter('unregistered')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                    typoFilter === 'unregistered'
                      ? 'bg-emerald-600 text-white shadow-2xs'
                      : 'bg-white text-slate-700 hover:bg-slate-100 border border-slate-200'
                  }`}
                >
                  Unregistered Candidates ({typosquat?.lookalikes?.filter(l => !l.resolves).length || 0})
                </button>
              </div>

              <div className="relative min-w-[200px]">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter lookalikes..."
                  value={typoSearch}
                  onChange={(e) => setTypoSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-hidden focus:border-purple-500"
                />
              </div>
            </div>

            {/* Lookalike Table */}
            {typosquat?.lookalikes && typosquat.lookalikes.length > 0 ? (
              <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold text-[11px]">
                    <tr>
                      <th className="py-2.5 px-4 font-sans">Lookalike Domain</th>
                      <th className="py-2.5 px-4 font-sans">Permutation Technique</th>
                      <th className="py-2.5 px-4 font-sans">Resolution Status</th>
                      <th className="py-2.5 px-4 font-sans">Resolved IP(s)</th>
                      <th className="py-2.5 px-4 font-sans text-right">Pivot</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {typosquat.lookalikes
                      .filter(l => {
                        if (typoFilter === 'resolving') return l.resolves;
                        if (typoFilter === 'unregistered') return !l.resolves;
                        return true;
                      })
                      .filter(l => {
                        if (!typoSearch) return true;
                        const q = typoSearch.toLowerCase();
                        return l.domain.toLowerCase().includes(q) || l.technique.toLowerCase().includes(q);
                      })
                      .map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/60 transition-colors">
                          <td className="py-2.5 px-4">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-900">{item.domain}</span>
                              {item.punycode && item.punycode !== item.domain && (
                                <span className="text-[10px] text-slate-400">({item.punycode})</span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-4">
                            <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-[10px] uppercase font-semibold">
                              {item.technique}
                            </span>
                          </td>
                          <td className="py-2.5 px-4">
                            {item.resolves ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300">
                                Live Threat (Resolving)
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-500">
                                Available / Unregistered
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-4 text-slate-600">
                            {item.ips && item.ips.length > 0 ? (
                              <span className="font-bold text-slate-800">{item.ips.join(', ')}</span>
                            ) : (
                              <span className="text-slate-400">-</span>
                            )}
                          </td>
                          <td className="py-2.5 px-4 text-right">
                            {item.resolves && (
                              <InvestigateAssetButton
                                ioc={item.domain}
                                iocType="domain"
                                compact={true}
                                onNavigateToJob={onNavigateToJob}
                              />
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-8 border border-dashed border-slate-200 rounded-xl text-center text-xs text-slate-500">
                No typosquatting permutations generated.
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB: INDICATOR NORMALISATION & CLASSIFICATION */}
        {/* ========================================================================= */}
        {activeTab === 'normalisation' && (
          <div className="p-6 space-y-6">
            {/* Header / Intro */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-200 gap-3">
              <div>
                <h4 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-blue-600" />
                  <span>Indicator Validation &amp; Normalisation Checklist</span>
                </h4>
                <p className="text-xs text-slate-500 mt-1">
                  Canonical syntax parsing, RFC special-purpose space detection, IDNA/Punycode homoglyphs, and Public Suffix separation.
                </p>
              </div>
              {normalisation?.is_valid && (
                <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300 self-start">
                  ✓ Syntax Valid ({normalisation.indicator_type.toUpperCase()})
                </span>
              )}
            </div>

            {/* Indicator Details Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-500">Original Raw Input</span>
                <p className="text-xs font-mono font-bold text-slate-800 break-all select-all">
                  {normalisation?.original_input || domainInfo.target}
                </p>
              </div>

              <div className="p-3.5 bg-blue-50/50 border border-blue-200 rounded-xl space-y-1">
                <span className="text-[10px] uppercase font-bold text-blue-600">Normalized Canonical Value</span>
                <p className="text-xs font-mono font-bold text-blue-900 break-all select-all flex items-center justify-between">
                  <span>{normalisation?.normalized_value || domainInfo.normalized_value || domainInfo.target}</span>
                  <button
                    onClick={() => copyToClipboard(normalisation?.normalized_value || domainInfo.target, 'canonical')}
                    className="text-blue-600 hover:text-blue-800 cursor-pointer ml-1 p-0.5"
                    title="Copy canonical value"
                  >
                    {copiedKey === 'canonical' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </p>
              </div>

              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-500">Indicator Classification</span>
                <p className="text-xs font-bold text-slate-800">
                  {normalisation?.ip_classification || (domainInfo.is_ip ? 'Public IP Address' : 'Internet FQDN')}
                </p>
              </div>

              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-500">Reverse DNS Eligibility</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                    normalisation?.rdns_eligible
                      ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                      : 'bg-amber-100 text-amber-800 border border-amber-200'
                  }`}>
                    {normalisation?.rdns_eligible ? 'Eligible' : 'Ineligible'}
                  </span>
                  <span className="text-[11px] text-slate-500 truncate" title={normalisation?.rdns_eligibility_reason}>
                    {normalisation?.rdns_eligibility_reason || 'Routable unicast'}
                  </span>
                </div>
              </div>
            </div>

            {/* Active IP Normalisation & RFC Classification Probe (Python ipaddress) */}
            {((normalisation?.active_ipaddress_findings && normalisation.active_ipaddress_findings.length > 0) || (domainInfo.active_recon_summary?.ip_findings && domainInfo.active_recon_summary.ip_findings.length > 0)) && (
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                <div className="flex items-center justify-between">
                  <h5 className="font-bold text-slate-700 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Active Python ipaddress Engine Verification</span>
                  </h5>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-100 text-indigo-800 border border-indigo-200">
                    Verified Attributes
                  </span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {(normalisation?.active_ipaddress_findings || domainInfo.active_recon_summary?.ip_findings || []).map((f: string, fIdx: number) => (
                    <span key={fIdx} className="px-2.5 py-1 rounded-lg text-xs font-mono bg-white border border-slate-200 text-slate-800 shadow-2xs">
                      ✓ {f}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Public Suffix List Breakdown (for Domains) */}
            {normalisation && !domainInfo.is_ip && (
              <div className="p-5 bg-white border border-slate-200 rounded-xl shadow-2xs space-y-3">
                <h5 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
                  <Globe className="w-4 h-4 text-blue-600" />
                  <span>Public Suffix List (PSL) Hierarchical Decomposition</span>
                </h5>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="text-[10px] uppercase font-bold text-slate-400">Subdomain Component</span>
                    <p className="text-sm font-mono font-bold text-slate-800 mt-0.5">
                      {normalisation.subdomain || <span className="text-slate-400 font-normal italic">(none)</span>}
                    </p>
                  </div>
                  <div className="p-3 bg-blue-50/60 rounded-lg border border-blue-200">
                    <span className="text-[10px] uppercase font-bold text-blue-500">Registrable Domain (SLD)</span>
                    <p className="text-sm font-mono font-bold text-blue-900 mt-0.5">
                      {normalisation.registrable_domain || domainInfo.target}
                    </p>
                  </div>
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="text-[10px] uppercase font-bold text-slate-400">Public Suffix / TLD</span>
                    <p className="text-sm font-mono font-bold text-slate-800 mt-0.5">
                      {normalisation.public_suffix ? `.${normalisation.public_suffix}` : <span className="text-slate-400 font-normal italic">(none)</span>}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Special Use Domains & SSRF Shield */}
            {normalisation && (normalisation.is_special_use_domain || normalisation.ssrf_risk || normalisation.is_private_rfc1918) && (
              <div className="p-4 bg-amber-50/80 border border-amber-200 rounded-xl space-y-2">
                <div className="flex items-center gap-2 text-amber-900 font-bold text-xs uppercase tracking-wider">
                  <ShieldAlert className="w-4 h-4 text-amber-700" />
                  <span>Boundary Security &amp; SSRF Isolation</span>
                </div>
                <p className="text-xs text-amber-800 leading-relaxed">
                  {normalisation.ssrf_mitigation_note || 'This indicator is classified as private or non-routable internal infrastructure. External threat intelligence queries and direct external socket connections are automatically restricted to mitigate Server-Side Request Forgery (SSRF) and data leakage.'}
                </p>
                {normalisation.special_use_category && (
                  <span className="inline-block px-2.5 py-0.5 rounded text-xs font-mono font-semibold bg-amber-200/70 text-amber-900 border border-amber-300">
                    Category: {normalisation.special_use_category}
                  </span>
                )}
              </div>
            )}

            {/* IDNA / Punycode & Unicode Homoglyphs */}
            {(() => {
              const spoofedList = normalisation?.spoofed_chars || (normalisation as any)?.homoglyphs || [];
              const hasPunyOrHomo = Boolean(normalisation?.has_punycode || normalisation?.is_punycode || normalisation?.is_homograph || (normalisation as any)?.has_homoglyphs || spoofedList.length > 0);
              const renderedUnicode = normalisation?.unicode_rendered || (normalisation as any)?.unicode_representation || domainInfo.target;

              if (!hasPunyOrHomo) return null;

              return (
                <div className="p-5 bg-purple-50/60 border border-purple-200 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <h5 className="text-xs font-bold uppercase tracking-wider text-purple-900 flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 text-purple-700" />
                      <span>Unicode Homoglyph / Confusable Impersonation Analysis</span>
                    </h5>
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-100 text-purple-800 border border-purple-300">
                      IDNA Decoded
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div className="p-3 bg-white rounded-lg border border-purple-100">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Punycode Form</span>
                      <p className="font-mono font-bold text-slate-800 mt-0.5">{normalisation?.normalized_value || domainInfo.target}</p>
                    </div>
                    <div className="p-3 bg-white rounded-lg border border-purple-100">
                      <span className="text-[10px] uppercase font-bold text-slate-400">Rendered Unicode</span>
                      <p className="font-sans text-base font-bold text-purple-900 mt-0.5">{renderedUnicode}</p>
                    </div>
                  </div>

                  {spoofedList.length > 0 && (
                    <div className="overflow-x-auto border border-purple-200 rounded-lg bg-white mt-3">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-purple-100/60 text-purple-900 uppercase font-bold text-[10px]">
                          <tr>
                            <th className="py-2 px-3">Spoofed Glyph</th>
                            <th className="py-2 px-3">Latin Lookalike</th>
                            <th className="py-2 px-3">Unicode Codepoint</th>
                            <th className="py-2 px-3">Character Name</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-purple-100 font-mono text-[11px]">
                          {spoofedList.map((c: any, i: number) => (
                            <tr key={i} className="hover:bg-purple-50/50">
                              <td className="py-2 px-3 font-sans text-base font-bold text-rose-600">{c.char}</td>
                              <td className="py-2 px-3 font-bold text-emerald-700">'{c.latin_lookalike || c.lookalike}'</td>
                              <td className="py-2 px-3 text-slate-600">{c.codepoint}</td>
                              <td className="py-2 px-3 font-sans text-slate-700">{c.name}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB: SUBDOMAIN TAKEOVER AUDIT */}
        {/* ========================================================================= */}
        {activeTab === 'takeover' && (
          <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-200 gap-3">
              <div>
                <h4 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                  <span>Subdomain Takeover &amp; Dangling CNAME Audit</span>
                </h4>
                <p className="text-xs text-slate-500 mt-1">
                  5-step automated vulnerability audit detecting orphaned DNS pointers across AWS S3, GitHub Pages, Heroku, Azure, Shopify, and more.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
                  (takeoverAnalysis?.has_high_risk_takeover || takeoverAnalysis?.has_takeover_risk || (takeoverAnalysis?.claimable_count || 0) > 0)
                    ? 'bg-rose-100 text-rose-800 border-rose-300 animate-pulse'
                    : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                }`}>
                  {(takeoverAnalysis?.has_high_risk_takeover || takeoverAnalysis?.has_takeover_risk || (takeoverAnalysis?.claimable_count || 0) > 0) ? 'Takeover Risk Detected' : 'No Takeover Risk'}
                </span>
              </div>
            </div>

            {/* Quick Metrics */}
            {(() => {
              const takeoverCandidates = (takeoverAnalysis?.dangling_cnames || (takeoverAnalysis as any)?.candidates || []) as Array<any>;
              const claimableCount = takeoverAnalysis?.claimable_count ?? (takeoverAnalysis as any)?.vulnerable_count ?? takeoverCandidates.length;
              const evaluatedCount = (takeoverAnalysis as any)?.evaluated_count ?? (domainInfo.attack_surface?.subdomains?.length || 0) + 1;
              return (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                      <span className="text-[10px] uppercase font-bold text-slate-500">Evaluated CNAME Records</span>
                      <p className="text-2xl font-black text-slate-800">{evaluatedCount}</p>
                      <p className="text-[11px] text-slate-500">Across discovered subdomains and CNAME chains</p>
                    </div>

                    <div className={`p-4 border rounded-xl space-y-1 ${
                      claimableCount > 0
                        ? 'bg-rose-50/70 border-rose-200'
                        : 'bg-emerald-50/70 border-emerald-200'
                    }`}>
                      <span className="text-[10px] uppercase font-bold text-slate-500">Vulnerable / Unclaimed</span>
                      <p className={`text-2xl font-black ${
                        claimableCount > 0 ? 'text-rose-600' : 'text-emerald-700'
                      }`}>
                        {claimableCount}
                      </p>
                      <p className="text-[11px] text-slate-600">Candidates with matched provider error fingerprints</p>
                    </div>

                    <div className="p-4 bg-blue-50/50 border border-blue-200 rounded-xl space-y-1">
                      <span className="text-[10px] uppercase font-bold text-blue-600">Cloud Provider Signatures</span>
                      <p className="text-2xl font-black text-blue-900">8 Services</p>
                      <p className="text-[11px] text-blue-700">AWS S3, GitHub Pages, Heroku, Azure, Shopify, Zendesk, Fastly, Surge</p>
                    </div>
                  </div>

                  {/* Candidates Table or Empty State */}
                  {takeoverCandidates.length > 0 ? (
                    <div className="border border-rose-200 rounded-xl overflow-hidden bg-white shadow-xs">
                      <div className="p-4 bg-rose-50/60 border-b border-rose-200 flex items-center justify-between">
                        <div className="font-bold text-xs text-rose-900 uppercase tracking-wider flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4 text-rose-600" />
                          <span>Dangling Subdomain Candidates Identified ({takeoverCandidates.length})</span>
                        </div>
                        <span className="text-xs text-rose-700 font-semibold">Immediate Action Required</span>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs text-left">
                          <thead className="bg-slate-50 text-slate-600 uppercase font-bold text-[10px] border-b border-slate-200">
                            <tr>
                              <th className="py-2.5 px-4">Subdomain</th>
                              <th className="py-2.5 px-4">CNAME Pointer Target</th>
                              <th className="py-2.5 px-4">Cloud Provider</th>
                              <th className="py-2.5 px-4">Severity</th>
                              <th className="py-2.5 px-4">Fingerprint Match</th>
                              <th className="py-2.5 px-4">Remediation Action</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {takeoverCandidates.map((c, idx) => (
                              <tr key={idx} className="hover:bg-rose-50/30 transition-colors">
                                <td className="py-3 px-4 font-mono font-bold text-slate-900">{c.subdomain || c.domain}</td>
                                <td className="py-3 px-4 font-mono text-slate-600">{c.cname_target}</td>
                                <td className="py-3 px-4">
                                  <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-100 text-slate-800 border border-slate-200">
                                    {c.service_provider || c.provider}
                                  </span>
                                </td>
                                <td className="py-3 px-4">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    c.severity === 'high'
                                      ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                      : 'bg-amber-100 text-amber-800 border border-amber-300'
                                  }`}>
                                    {c.severity}
                                  </span>
                                </td>
                                <td className="py-3 px-4 text-slate-700 font-mono text-[11px]">{c.signature || c.fingerprint_match || '-'}</td>
                                <td className="py-3 px-4 text-slate-800 font-medium">{c.remediation}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 border border-dashed border-emerald-200 rounded-xl bg-emerald-50/30 text-center space-y-2">
                      <CheckCircle2 className="w-8 h-8 text-emerald-600 mx-auto" />
                      <h5 className="text-sm font-bold text-emerald-900">Zero Dangling CNAME Records Detected</h5>
                      <p className="text-xs text-emerald-700 max-w-lg mx-auto">
                        All evaluated CNAME records and subdomains either point to active legitimate assets or do not expose orphaned cloud bucket/app fingerprints.
                      </p>
                    </div>
                  )}

                  {/* Audited Cloud Provider Takeover Signatures & Fingerprint Database */}
                  <div className="border border-blue-200 rounded-xl overflow-hidden bg-white shadow-xs">
                    <div className="p-4 bg-blue-50/70 border-b border-blue-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-0.5">
                        <div className="font-bold text-xs text-blue-950 uppercase tracking-wider flex items-center gap-1.5">
                          <Cloud className="w-4 h-4 text-blue-600" />
                          <span>Audited Cloud Provider Takeover Signatures ({filteredSignatures.length} of {CLOUD_TAKEOVER_SIGNATURES.length} Active)</span>
                        </div>
                        <p className="text-[11px] text-blue-700">
                          CNAME canonical routing patterns, HTTP response body error fingerprints, and remediation protocols.
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <select
                          value={signatureProviderFilter}
                          onChange={(e) => setSignatureProviderFilter(e.target.value)}
                          className="px-2.5 py-1 text-xs border border-blue-200 rounded-lg bg-white text-slate-800 focus:outline-hidden focus:ring-1 focus:ring-blue-500 cursor-pointer"
                        >
                          <option value="all">All Providers ({CLOUD_TAKEOVER_SIGNATURES.length})</option>
                          {CLOUD_TAKEOVER_SIGNATURES.map((s) => (
                            <option key={s.provider} value={s.provider}>{s.provider}</option>
                          ))}
                        </select>
                        <input
                          type="text"
                          value={signatureSearch}
                          onChange={(e) => setSignatureSearch(e.target.value)}
                          placeholder="Search signatures or fingerprints..."
                          className="px-2.5 py-1 text-xs border border-blue-200 rounded-lg bg-white text-slate-800 placeholder-slate-400 focus:outline-hidden focus:ring-1 focus:ring-blue-500 w-52 font-mono"
                        />
                      </div>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs text-left">
                        <thead className="bg-slate-50 text-slate-600 uppercase font-bold text-[10px] border-b border-slate-200">
                          <tr>
                            <th className="py-2.5 px-4">Cloud Provider</th>
                            <th className="py-2.5 px-4">CNAME Pointer Target Pattern</th>
                            <th className="py-2.5 px-4">Error Response Body Fingerprint</th>
                            <th className="py-2.5 px-4">Unclaimed Status</th>
                            <th className="py-2.5 px-4">Severity</th>
                            <th className="py-2.5 px-4">Actionable Remediation</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {filteredSignatures.map((sig, sIdx) => (
                            <tr key={sIdx} className="hover:bg-blue-50/30 transition-colors">
                              <td className="py-3 px-4 font-bold text-slate-900 whitespace-nowrap">
                                <div className="flex items-center gap-1.5">
                                  <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-100 text-blue-900 border border-blue-200">
                                    {sig.provider}
                                  </span>
                                </div>
                                <span className="text-[10px] text-slate-500 font-normal block mt-1">{sig.serviceType}</span>
                              </td>
                              <td className="py-3 px-4 font-mono text-[11px]">
                                <span className="font-bold text-slate-800 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                                  {sig.cnamePattern}
                                </span>
                                <span className="text-[10px] text-slate-400 block font-mono mt-1 truncate max-w-xs" title={sig.cnameRegex}>
                                  Regex: {sig.cnameRegex}
                                </span>
                              </td>
                              <td className="py-3 px-4">
                                <span className="px-2 py-1 rounded font-mono text-[11px] font-bold bg-amber-50 text-amber-900 border border-amber-300 inline-block">
                                  &quot;{sig.fingerprint}&quot;
                                </span>
                              </td>
                              <td className="py-3 px-4 font-mono text-[11px]">
                                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-bold border border-slate-200">
                                  {sig.unclaimedStatus}
                                </span>
                              </td>
                              <td className="py-3 px-4">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                  sig.severity === 'high'
                                    ? 'bg-rose-100 text-rose-800 border border-rose-300'
                                    : 'bg-amber-100 text-amber-800 border border-amber-300'
                                }`}>
                                  {sig.severity}
                                </span>
                              </td>
                              <td className="py-3 px-4 text-slate-700 text-[11px] leading-relaxed max-w-sm">
                                {sig.remediation}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              );
            })()}

            {/* 5-Step Methodology Card */}
            <div className="p-5 bg-slate-50 border border-slate-200 rounded-xl space-y-3 text-xs">
              <h5 className="font-bold text-slate-800 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-blue-600" />
                <span>5-Step Subdomain Takeover Verification Protocol</span>
              </h5>
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 pt-1 text-[11px]">
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <div className="font-bold text-blue-600 mb-0.5">1. CNAME Discovery</div>
                  <p className="text-slate-600">Scan zone records and Certificate Transparency logs for aliases.</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <div className="font-bold text-blue-600 mb-0.5">2. Canonical Resolution</div>
                  <p className="text-slate-600">Trace pointer chains to third-party cloud hosting endpoints.</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <div className="font-bold text-blue-600 mb-0.5">3. Fingerprint Match</div>
                  <p className="text-slate-600">Query HTTP responses for provider 404/unclaimed patterns.</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <div className="font-bold text-blue-600 mb-0.5">4. Safe Verification</div>
                  <p className="text-slate-600">Inspect zone authority without hostile exploitation.</p>
                </div>
                <div className="p-2.5 bg-white rounded-lg border border-slate-200">
                  <div className="font-bold text-blue-600 mb-0.5">5. Remediation</div>
                  <p className="text-slate-600">Delete orphaned DNS records or claim resource in tenant.</p>
                </div>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
