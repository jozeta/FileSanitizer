import React, { useState } from 'react';
import {
  Terminal,
  ShieldAlert,
  Copy,
  Check,
  Clock,
  Layers,
  Globe,
  AlertTriangle,
  Zap
} from 'lucide-react';
import { LnkInfo, Finding } from '../types';
import { formatBytes } from '../utils/formatters';

interface LnkCardProps {
  lnkInfo?: LnkInfo | null;
  filename?: string;
  findings?: Finding[];
}

export const LnkCard: React.FC<LnkCardProps> = ({ lnkInfo, filename = 'shortcut.lnk', findings = [] }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!lnkInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Terminal className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No LNK forensic metadata available for this file.</p>
      </div>
    );
  }

  const {
    header,
    timestamps,
    targets_and_paths,
    deobfuscated_payload,
    lolbins = [],
    icon_spoofed = false,
    icon_spoof_details,
    overlay,
    extra_blocks = [],
    urls = []
  } = lnkInfo;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const isStealthMode = header.show_command === 7;
  const lnkFindings = findings.filter(f =>
    f.title.toLowerCase().includes('lnk') ||
    f.category === 'evasion' ||
    f.category === 'social_engineering' ||
    f.title.toLowerCase().includes('stealth window') ||
    f.title.toLowerCase().includes('overlay')
  );

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-amber-50 text-amber-600 rounded-2xl shrink-0">
            <Terminal className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Forensic Windows Shell Link (.LNK) Dissection
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-slate-100 text-slate-700 border border-slate-200 font-mono">
                {filename}
              </span>
              {icon_spoofed && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-700 border border-rose-300 animate-pulse">
                  ⚠️ Icon Spoofed (Masquerading)
                </span>
              )}
              {isStealthMode && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-50 text-purple-700 border border-purple-300">
                  ⚠️ Stealth Mode (SW_SHOWMINNOACTIVE)
                </span>
              )}
              {overlay && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-red-50 text-red-700 border border-red-300">
                  ⚠️ Appended Overlay ({formatBytes(overlay.size)})
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              Binary parser conforming to Microsoft [MS-SHLLINK] specification. Unpacks command arguments, Base64 payloads, stealth execution flags, and trailing overlay structures.
            </p>
          </div>
        </div>

        {/* LOLBin Quick Badges */}
        {lolbins.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            {lolbins.map((lb, idx) => (
              <span key={idx} className="px-2.5 py-1 rounded-xl bg-rose-100 text-rose-800 border border-rose-300 font-bold flex items-center gap-1">
                <Zap className="w-3 h-3 text-rose-600" />
                {lb.binary}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Security Findings & Evasion Alerts */}
      {lnkFindings.length > 0 && (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-2xl space-y-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-600 shrink-0" />
            <span className="text-xs font-bold text-rose-900 uppercase tracking-wide">
              Identified Threat Vectors ({lnkFindings.length})
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
            {lnkFindings.map((f, idx) => (
              <div key={idx} className="p-2.5 bg-white/90 border border-rose-200/80 rounded-xl text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <strong className="text-rose-900">{f.title}</strong>
                  <span className={`text-[10px] uppercase font-bold px-1.5 py-0.2 rounded ${
                    f.severity === 'critical' ? 'bg-rose-600 text-white' : 'bg-amber-100 text-amber-800'
                  }`}>
                    {f.severity}
                  </span>
                </div>
                <p className="text-slate-600 text-[11px] leading-relaxed">{f.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Target Command & Argument Execution */}
      <div className="space-y-4">
        <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-blue-600" />
              Target Execution Command
            </span>
            {targets_and_paths.target_command && (
              <button
                onClick={() => copyToClipboard(targets_and_paths.target_command || '', 'target_cmd')}
                className="text-xs text-blue-600 hover:text-blue-800 flex items-center gap-1 cursor-pointer font-semibold"
              >
                {copiedKey === 'target_cmd' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey === 'target_cmd' ? 'Copied' : 'Copy Command'}</span>
              </button>
            )}
          </div>
          <div className="p-3 bg-white rounded-xl border border-slate-200 font-mono text-xs text-slate-900 break-all select-all">
            {targets_and_paths.target_command || targets_and_paths.relative_path || 'No target command recorded in LinkInfo'}
          </div>

          {/* Full Command Line Arguments */}
          {targets_and_paths.arguments && (
            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                  Raw Command-Line Arguments
                </span>
                <button
                  onClick={() => copyToClipboard(targets_and_paths.arguments || '', 'arguments')}
                  className="text-[11px] text-slate-600 hover:text-slate-900 flex items-center gap-1 cursor-pointer"
                >
                  {copiedKey === 'arguments' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'arguments' ? 'Copied' : 'Copy Arguments'}</span>
                </button>
              </div>
              <div className="p-3 bg-slate-900 text-emerald-400 rounded-xl font-mono text-xs break-all select-all leading-relaxed max-h-48 overflow-y-auto">
                {targets_and_paths.arguments}
              </div>
            </div>
          )}

          {/* Deobfuscated / Decoded PowerShell Payload */}
          {deobfuscated_payload && (
            <div className="p-4 bg-emerald-50/80 border border-emerald-300 rounded-2xl space-y-2 mt-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1 bg-emerald-600 text-white rounded-md">
                    <Check className="w-3.5 h-3.5" />
                  </div>
                  <div>
                    <h5 className="font-bold text-xs text-emerald-950 uppercase tracking-wide">
                      Deobfuscated Base64 / Unicode Payload
                    </h5>
                    <span className="text-[10px] text-emerald-700">
                      Decoded directly from -EncodedCommand / Unicode UTF-16LE arguments
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => copyToClipboard(deobfuscated_payload, 'deobfuscated')}
                  className="text-xs text-emerald-800 hover:text-emerald-950 font-semibold flex items-center gap-1 cursor-pointer bg-white px-2.5 py-1 rounded-lg border border-emerald-300"
                >
                  {copiedKey === 'deobfuscated' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedKey === 'deobfuscated' ? 'Copied' : 'Copy Decoded Code'}</span>
                </button>
              </div>
              <pre className="p-3 bg-white rounded-xl border border-emerald-200 font-mono text-xs text-emerald-900 overflow-x-auto whitespace-pre-wrap break-all max-h-60">
                {deobfuscated_payload}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Forensic Properties Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Working Directory */}
        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
            Working Directory
          </span>
          <div className="text-xs font-mono text-slate-800 truncate" title={targets_and_paths.working_directory || 'N/A'}>
            {targets_and_paths.working_directory || '<Current Directory>'}
          </div>
        </div>

        {/* Show Command / Window Mode */}
        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
            Window Mode (ShowCommand)
          </span>
          <div className={`text-xs font-semibold ${isStealthMode ? 'text-purple-700 font-bold' : 'text-slate-800'}`}>
            {header.show_command_desc}
          </div>
        </div>

        {/* Icon Location & Spoofing */}
        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
            Icon Location &amp; Index
          </span>
          <div className="text-xs font-mono text-slate-800 truncate" title={targets_and_paths.icon_location || 'Default'}>
            {targets_and_paths.icon_location ? `${targets_and_paths.icon_location}, index ${header.icon_index}` : 'Default Shell Icon'}
          </div>
          {icon_spoofed && (
            <p className="text-[10px] text-rose-700 font-medium pt-0.5">
              {icon_spoof_details}
            </p>
          )}
        </div>

        {/* Target File Size */}
        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
            Target Binary File Size
          </span>
          <div className="text-xs font-mono font-semibold text-slate-800">
            {formatBytes(header.target_file_size)} ({header.target_file_size.toLocaleString()} bytes)
          </div>
        </div>

        {/* Link Flags */}
        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
            Link Flags &amp; Attributes
          </span>
          <div className="text-xs font-mono text-slate-800">
            Flags: <span className="font-bold">{header.link_flags}</span> | Attr: {header.file_attributes}
          </div>
        </div>

        {/* Shell Item ID List Entries */}
        <div className="p-4 bg-slate-50 rounded-2xl border border-slate-200 space-y-1">
          <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
            Shell Item IDs ({targets_and_paths.id_list_items?.length || 0})
          </span>
          <div className="text-xs font-mono text-slate-700 truncate" title={(targets_and_paths.id_list_items || []).join(', ')}>
            {(targets_and_paths.id_list_items || []).length > 0
              ? (targets_and_paths.id_list_items || []).join(' → ')
              : 'None recorded'}
          </div>
        </div>
      </div>

      {/* Timestamps (Windows FILETIME 64-bit UTC) */}
      <div className="p-4 bg-slate-50/70 border border-slate-200 rounded-2xl space-y-3">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-600" />
          <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
            Target Forensic Timestamps (Windows FILETIME)
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-semibold block">Creation Time</span>
            <div className="font-mono text-slate-800 font-semibold">{timestamps.creation_time || 'N/A'}</div>
          </div>
          <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-semibold block">Last Access Time</span>
            <div className="font-mono text-slate-800 font-semibold">{timestamps.access_time || 'N/A'}</div>
          </div>
          <div className="p-3 bg-white rounded-xl border border-slate-200 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-semibold block">Last Write Time</span>
            <div className="font-mono text-slate-800 font-semibold">{timestamps.write_time || 'N/A'}</div>
          </div>
        </div>
      </div>

      {/* Appended Trailing Overlay Alert */}
      {overlay && (
        <div className="p-4 bg-rose-50/80 border border-rose-300 rounded-2xl space-y-3">
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-3">
              <div className="p-2 bg-rose-600 text-white rounded-xl">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-sm text-rose-950">
                  Trailing Overlay Payload Detected ({formatBytes(overlay.size)})
                </h4>
                <p className="text-xs text-rose-800 leading-relaxed mt-0.5">
                  Attackers append binary data after the 0x00000000 terminal block of the LNK structure. The Windows shell ignores this overlay when creating the shortcut, while secondary scripts read and extract the payload.
                </p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-600 text-white uppercase tracking-wider shrink-0">
              {overlay.is_executable ? 'PE Executable' : (overlay.is_zip ? 'ZIP Archive' : 'Binary Payload')}
            </span>
          </div>

          <div className="p-3 bg-white rounded-xl border border-rose-200 text-xs font-mono space-y-1.5">
            <div className="flex items-center justify-between text-slate-700">
              <span>Overlay SHA-256:</span>
              <span className="font-bold select-all">{overlay.sha256 || 'N/A'}</span>
            </div>
            {overlay.preview && (
              <div className="space-y-1 pt-1">
                <span className="text-[10px] text-slate-400 uppercase font-sans font-bold">Payload Preview (Hex / ASCII):</span>
                <div className="p-2 bg-slate-900 text-rose-300 rounded-lg text-[11px] break-all select-all font-mono">
                  {overlay.preview}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ExtraData Blocks */}
      {extra_blocks.length > 0 && (
        <div className="space-y-2">
          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
            <Layers className="w-4 h-4 text-slate-500" />
            ExtraData Blocks ({extra_blocks.length})
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {extra_blocks.map((eb, idx) => (
              <div key={idx} className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-800">{eb.name}</div>
                  <div className="text-[10px] font-mono text-slate-400">{eb.signature}</div>
                </div>
                <span className="text-[11px] font-mono text-slate-500">{eb.size} B</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Extracted URLs */}
      {urls.length > 0 && (
        <div className="space-y-2">
          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
            <Globe className="w-4 h-4 text-emerald-600" />
            Discovered Remote URLs ({urls.length})
          </span>
          <div className="space-y-1.5">
            {urls.map((u, idx) => (
              <div key={idx} className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-800 truncate mr-2 select-all">{u}</span>
                <button
                  onClick={() => copyToClipboard(u, `url_${idx}`)}
                  className="text-slate-500 hover:text-slate-800 cursor-pointer p-1"
                >
                  {copiedKey === `url_${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
