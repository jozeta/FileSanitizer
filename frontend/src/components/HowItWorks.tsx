import React from 'react';
import { 
  ShieldCheck, 
  Search, 
  Cpu, 
  FileText, 
  Lock, 
  EyeOff, 
  Wrench, 
  CheckCircle2, 
  ArrowRight, 
  AlertTriangle, 
  Server, 
  Clock, 
  GlobeLock,
  Layers,
  Sparkles,
  Laptop
} from 'lucide-react';

interface HowItWorksProps {
  onGoToSanitizer: () => void;
  onGoToFormats: () => void;
}

export const HowItWorks: React.FC<HowItWorksProps> = ({ onGoToSanitizer, onGoToFormats }) => {
  const steps = [
    {
      num: "01",
      title: "Safe Ingestion, Host Discovery & Anti-SSRF Protection",
      icon: GlobeLock,
      tag: "Ingestion & Recon",
      tagColor: "bg-blue-50 text-blue-700 border-blue-200",
      description: "Upload local files or enter remote URLs, domains, or IPv4/IPv6 indicators. Domain targets trigger automated Host Discovery: authoritative DNS records, WHOIS/RDAP ownership, BGP routing & ASN prefixes, passive exposure harvesting (robots.txt, sitemaps, .well-known), FCrDNS verification, Wayback Machine snapshots, and sandboxed browser rendering with visual Punycode homograph defense. Remote file fetches pass through recursive DNS checking and anti-SSRF filters, barring cloud metadata (169.254.169.254), loopbacks, and RFC 1918 private subnets."
    },
    {
      num: "02",
      title: "Magic-Byte Forensics, Binary Headers & Hashes",
      icon: Search,
      tag: "Verification & Hashing",
      tagColor: "bg-indigo-50 text-indigo-700 border-indigo-200",
      description: "Never trust file extensions. FileSanitizer parses binary magic bytes across Windows PE, Linux ELF, macOS Mach-O, Windows EVTX logs, LNK shortcuts, PCAP packet traces, and OLE/ZIP packages, eliminating double-extension spoofing (e.g. invoice.pdf.exe). Cryptographic SHA-256, SHA-1, MD5, and fuzzy hashes are cataloged as immutable forensic identifiers."
    },
    {
      num: "03",
      title: "Streaming Antivirus & Threat Intelligence Feeds",
      icon: ShieldCheck,
      tag: "Malware & CTI Scanners",
      tagColor: "bg-emerald-50 text-emerald-700 border-emerald-200",
      description: "Samples are streamed over an isolated socket to a dedicated ClamAV daemon equipped with community signature feeds (SecuriteInfo, Sanesecurity) without host execution. Fingerprinted technologies, C2 indicators, and hashes are correlated against CISA Known Exploited Vulnerabilities (KEV), FIRST EPSS (Exploit Prediction Scoring System), ThreatFox (abuse.ch), CIRCL Hashlookup (NSRL benign database), and VirusTotal."
    },
    {
      num: "04",
      title: "Structural Decomposition & Forensic Timelines",
      icon: Layers,
      tag: "Deep Decomposition",
      tagColor: "bg-purple-50 text-purple-700 border-purple-200",
      description: "Files are unpacked to atomic primitives: Windows EVTX event streams (generating chronological timelines of logons, process launches, and privilege escalations), PCAP network conversations (HTTP sessions, cleartext credentials, SNI hosts), PDF cross-reference tables and object streams, OpenXML packages, OLE compound files, Windows LNK shell links, and nested archives. Directory traversals (../../) and zip bombs (>100:1 ratio) are blocked."
    },
    {
      num: "05",
      title: "Active Content & Binary Exploit Mitigations",
      icon: Cpu,
      tag: "Exploit Disarmament",
      tagColor: "bg-amber-50 text-amber-700 border-amber-200",
      description: "Static inspection without code execution identifies embedded VBA macros, Excel 4.0 XLM macro sheets, ActiveX controls, remote template injection (attachedTemplate), PDF JavaScript actions, /Launch hooks, CSV formula/DDE execution (=cmd|...), and browser extension permission misuse. Compiled native binaries undergo checksec v3 mitigation audits: Stack Canary, NX / DEP, ASLR / PIE, RELRO, Fortify Source, SafeSEH, and CFG."
    },
    {
      num: "06",
      title: "Privacy, Optical OCR & Forensic Telemetry",
      icon: EyeOff,
      tag: "Privacy & Provenance",
      tagColor: "bg-rose-50 text-rose-700 border-rose-200",
      description: "Exposes sensitive data that compromises privacy: precise GPS coordinates, camera make/model/serial numbers, internal author and modifier identities, organizational emails, revision history, and reviewer comments. Optical Character Recognition (OCR) extracts hidden text from photos; QR code scanners decode hidden payloads; and C2PA Content Credentials audit AI-generated imagery and synthetic deepfakes."
    },
    {
      num: "07",
      title: "Content Disarm & Reconstruction (CDR)",
      icon: Wrench,
      tag: "Reconstruction",
      tagColor: "bg-cyan-50 text-cyan-700 border-cyan-200",
      description: "Rather than attempting to patch infected documents, Content Disarm & Reconstruction rebuilds clean files from safe raw primitives. Office files have macros purged and relationships neutralized. Images have pixel buffers re-encoded. PDFs can be flattened into high-resolution rendered pixel pages. Windows LNK shortcuts have arguments scrubbed, and archives are re-bundled with safe data only."
    },
    {
      num: "08",
      title: "Verification Matrix, Graph Correlation & Dossiers",
      icon: CheckCircle2,
      tag: "Validation & Graph",
      tagColor: "bg-teal-50 text-teal-700 border-teal-200",
      description: "The sanitized file undergoes complete secondary multi-scanner re-inspection. An automated before-and-after comparison matrix proves that metadata fields dropped to zero, active macros were eradicated, and URLs were neutralized. Discovered indicators automatically link across multiple analyzed files in the unified Incident Correlation Graph, with one-click asset investigation pivots."
    }
  ];

  return (
    <div className="max-w-[80rem] mx-auto py-10 px-4 sm:px-6 lg:px-8 space-y-12">
      {/* Hero Section */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-slate-100 rounded-full text-xs font-mono text-slate-700 border border-slate-200">
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span>Zero-Trust Content Disarm and Reconstruction</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
          How FileSanitizer Works
        </h1>
        <p className="text-base sm:text-lg text-slate-600 leading-relaxed">
          Traditional security relies on detecting known malware signatures. FileSanitizer assumes untrusted files 
          contain active risks, deconstructs them into safe primitives, and reconstructs clean, production-ready documents.
        </p>
      </div>

      {/* Philosophy Card: Detection vs CDR */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
        <div className="space-y-3 pr-0 md:pr-4 border-b md:border-b-0 md:border-r border-slate-200 pb-6 md:pb-0">
          <div className="flex items-center gap-2 text-rose-600 font-semibold text-sm">
            <AlertTriangle className="w-4 h-4" />
            <span>Traditional Antivirus (Passive Detection)</span>
          </div>
          <h3 className="text-lg font-bold text-slate-900">Looks for Known Signatures</h3>
          <ul className="text-sm text-slate-600 space-y-2 font-normal">
            <li className="flex items-start gap-2">
              <span className="text-rose-500 font-bold">•</span>
              <span>Vulnerable to zero-day exploits and polymorphic malware.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-rose-500 font-bold">•</span>
              <span>Leaves sensitive metadata (GPS coordinates, author names, deleted text) untouched.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-rose-500 font-bold">•</span>
              <span>Allows legitimate documents with malicious active macros or external triggers to pass through.</span>
            </li>
          </ul>
        </div>

        <div className="space-y-3 pl-0 md:pl-4">
          <div className="flex items-center gap-2 text-emerald-600 font-semibold text-sm">
            <ShieldCheck className="w-4 h-4" />
            <span>FileSanitizer CDR (Active Disarmament)</span>
          </div>
          <h3 className="text-lg font-bold text-slate-900">Enforces Zero-Trust Sanitization</h3>
          <ul className="text-sm text-slate-600 space-y-2 font-normal">
            <li className="flex items-start gap-2">
              <span className="text-emerald-500 font-bold">•</span>
              <span>Disarms active content regardless of whether it is recognized by signature databases.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-500 font-bold">•</span>
              <span>Deep-cleans all EXIF, GPS, camera serials, and revision history.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-500 font-bold">•</span>
              <span>Rebuilds verified clean files with visual before-and-after proof.</span>
            </li>
          </ul>
        </div>
      </div>

      {/* 8-Stage Pipeline Section */}
      <div className="space-y-6">
        <div className="text-center max-w-xl mx-auto">
          <h2 className="text-2xl font-bold text-slate-900 tracking-tight">The 8-Stage Sanitization Pipeline</h2>
          <p className="text-sm text-slate-500 mt-1">Every ingested file undergoes an end-to-end multi-scanner workflow.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {steps.map((s, idx) => {
            const Icon = s.icon;
            return (
              <div 
                key={idx}
                className="bg-white border border-slate-200 rounded-2xl p-5 hover:border-slate-300 transition-all shadow-sm flex flex-col justify-between"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="text-xs font-mono font-bold text-slate-400 bg-slate-100 px-2 py-0.5 rounded">
                        {s.num}
                      </span>
                      <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${s.tagColor}`}>
                        {s.tag}
                      </span>
                    </div>
                    <div className="w-8 h-8 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-center text-slate-700">
                      <Icon className="w-4 h-4" />
                    </div>
                  </div>

                  <h3 className="text-base font-semibold text-slate-900">
                    {s.title}
                  </h3>

                  <p className="text-xs text-slate-600 leading-relaxed font-normal">
                    {s.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Security Architecture Guarantees */}
      <div className="bg-slate-50 border border-slate-200 text-slate-800 rounded-3xl p-8 sm:p-10 shadow-sm space-y-6">
        <div className="max-w-2xl space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 bg-white border border-slate-200 rounded-full text-xs font-mono text-slate-600">
            <Lock className="w-3.5 h-3.5 text-blue-600" />
            <span>Hardened Docker Architecture</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900">Security & Isolation Guarantees</h2>
          <p className="text-sm text-slate-600 leading-relaxed">
            Designed from day one for self-hosted deployment in high-security, air-gapped, or regulated environments.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 rounded-2xl p-4 space-y-2 shadow-xs">
            <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-slate-900">Non-Root & Zero Caps</h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Containers run under unprivileged UIDs (1001) with Linux capabilities dropped (<code className="font-mono text-slate-700 bg-slate-100 px-1 py-0.5 rounded">cap_drop: ALL</code>).
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-4 space-y-2 shadow-xs">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center">
              <Laptop className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-slate-900">Cross-Platform Docker</h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Natively runs across macOS (Apple Silicon & Intel), Windows 11 (x64 AMD/Intel via WSL2), and Linux (amd64 & arm64).
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-4 space-y-2 shadow-xs">
            <div className="w-8 h-8 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center">
              <GlobeLock className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-slate-900">Anti-SSRF & Network Shield</h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Recursive DNS checks block requests to cloud metadata (169.254.169.254), loopbacks, and RFC 1918 subnets across bridge networks.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-4 space-y-2 shadow-xs">
            <div className="w-8 h-8 rounded-lg bg-amber-50 text-amber-600 flex items-center justify-center">
              <Clock className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-slate-900">Isolated 30-Min Auto-Purge</h4>
            <p className="text-xs text-slate-500 leading-relaxed">
              Originals reside in UUID directories and are never overwritten; daemons permanently purge workspaces and screenshots every 30 mins.
            </p>
          </div>
        </div>
      </div>

      {/* Call to Actions */}
      <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-2">
        <button
          onClick={onGoToSanitizer}
          className="w-full sm:w-auto px-6 py-3 bg-slate-900 hover:bg-blue-600 text-white font-medium text-sm rounded-xl shadow-sm transition-all flex items-center justify-center gap-2 cursor-pointer"
        >
          <span>Start Sanitizing Files</span>
          <ArrowRight className="w-4 h-4" />
        </button>

        <button
          onClick={onGoToFormats}
          className="w-full sm:w-auto px-6 py-3 bg-white hover:bg-slate-50 text-slate-700 font-medium text-sm rounded-xl border border-slate-200 shadow-sm transition-colors flex items-center justify-center gap-2 cursor-pointer"
        >
          <span>View Supported Formats & Checks</span>
          <FileText className="w-4 h-4 text-slate-400" />
        </button>
      </div>
    </div>
  );
};
