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
  Sparkles
} from 'lucide-react';

interface HowItWorksProps {
  onGoToSanitizer: () => void;
  onGoToFormats: () => void;
}

export const HowItWorks: React.FC<HowItWorksProps> = ({ onGoToSanitizer, onGoToFormats }) => {
  const steps = [
    {
      num: "01",
      title: "Safe Ingestion & SSRF Protection",
      icon: GlobeLock,
      tag: "Ingestion",
      tagColor: "bg-blue-50 text-blue-700 border-blue-200",
      description: "Upload local files or enter a remote URL. Remote URLs pass through recursive DNS resolution and strict SSRF filters, blocking loopback, cloud metadata (169.254.169.254), and private RFC 1918 subnets. Pre-download reputation checks query watchlists (URLhaus, VirusTotal) for active malware or scam indicators."
    },
    {
      num: "02",
      title: "Magic-Byte Identification & Hashing",
      icon: Search,
      tag: "Verification",
      tagColor: "bg-indigo-50 text-indigo-700 border-indigo-200",
      description: "Never trust the file extension. FileSanitizer analyzes binary headers and hex magic bytes to discover true MIME types, exposing dangerous extension-spoofing tricks (e.g. invoice.pdf.exe). Cryptographic SHA-256, SHA-1, and MD5 hashes are generated as permanent forensic identifiers."
    },
    {
      num: "03",
      title: "Streaming Antivirus Inspection",
      icon: ShieldCheck,
      tag: "Antivirus",
      tagColor: "bg-emerald-50 text-emerald-700 border-emerald-200",
      description: "Uploaded files are streamed over an isolated TCP socket to a dedicated ClamAV daemon container without ever executing on the host. If active trojans, ransomware, or virus signatures are detected, the file is immediately quarantined and clean file generation is blocked by default."
    },
    {
      num: "04",
      title: "Deep Structural Decomposition",
      icon: Layers,
      tag: "Decomposition",
      tagColor: "bg-purple-50 text-purple-700 border-purple-200",
      description: "Files are unpacked down to their atomic components: PDF cross-reference tables and indirect objects, OpenXML relationship packages, OLE compound storages, SVG Document Object Models (DOM), and recursive archive trees. Directory traversal paths (../../) and zip bombs (>100x compression) are trapped."
    },
    {
      num: "05",
      title: "Active Content & Exploit Disarmament",
      icon: Cpu,
      tag: "Exploit Defense",
      tagColor: "bg-amber-50 text-amber-700 border-amber-200",
      description: "Static inspection without code execution identifies embedded Visual Basic for Applications (VBA) macros, ActiveX controls, remote template injection (attachedTemplate), PDF JavaScript actions, /Launch commands, external URI actions, CSV formula/DDE injections (=cmd|...), and SVG inline scripts."
    },
    {
      num: "06",
      title: "Privacy & Metadata Extraction",
      icon: EyeOff,
      tag: "Privacy Audit",
      tagColor: "bg-rose-50 text-rose-700 border-rose-200",
      description: "Identifies hidden information that could compromise privacy: precise GPS geographic coordinates, camera make/model/serial numbers, internal author identities, organization names, tracked revision history, deleted document drafts, reviewer comments, and embedded external URLs."
    },
    {
      num: "07",
      title: "Content Disarm & Reconstruction (CDR)",
      icon: Wrench,
      tag: "Reconstruction",
      tagColor: "bg-cyan-50 text-cyan-700 border-cyan-200",
      description: "Rather than attempting to patch broken files, Content Disarm & Reconstruction rebuilds clean files from safe raw primitives. Office files have macros purged and relationships neutralized. Images have pixel buffers re-encoded. PDFs can be flattened into high-resolution rendered pixel pages."
    },
    {
      num: "08",
      title: "Post-Sanitization Verification Matrix",
      icon: CheckCircle2,
      tag: "Validation",
      tagColor: "bg-teal-50 text-teal-700 border-teal-200",
      description: "The sanitized file undergoes full secondary re-analysis. An automated before-and-after comparison matrix proves that metadata fields dropped to zero, macros were eradicated, URLs were removed, and the file passes secondary ClamAV inspection before you download it."
    }
  ];

  return (
    <div className="max-w-6xl mx-auto py-10 px-4 sm:px-6 lg:px-8 space-y-12">
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
      <div className="bg-slate-900 text-white rounded-3xl p-8 sm:p-10 shadow-lg space-y-6">
        <div className="max-w-2xl space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 bg-white/10 rounded-full text-xs font-mono text-slate-300">
            <Lock className="w-3.5 h-3.5 text-blue-400" />
            <span>Hardened Docker Architecture</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight">Security & Isolation Guarantees</h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            Designed from day one for self-hosted deployment in high-security, air-gapped, or regulated environments.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white/5 border border-white/10 rounded-2xl p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-blue-500/20 text-blue-400 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-white">Non-Root & Zero Caps</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Containers run under unprivileged UIDs with Linux capabilities dropped (<code className="font-mono text-slate-300">cap_drop: ALL</code>).
            </p>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-2xl p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <Lock className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-white">Immutable Originals</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Original files are stored in isolated UUID directories and never overwritten. Clean files are completely new artifacts.
            </p>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-2xl p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-purple-500/20 text-purple-400 flex items-center justify-center">
              <GlobeLock className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-white">Anti-SSRF Protection</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Strict DNS checking blocks requests to localhost, AWS/GCP cloud metadata, Docker internal networks, and private IP blocks.
            </p>
          </div>

          <div className="bg-white/5 border border-white/10 rounded-2xl p-4 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-amber-500/20 text-amber-400 flex items-center justify-center">
              <Clock className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-semibold text-white">30-Min Auto-Purge</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Background cleanup daemon permanently purges job workspaces, original samples, and screenshots every 30 minutes.
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
