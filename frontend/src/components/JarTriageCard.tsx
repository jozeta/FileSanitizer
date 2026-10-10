import React, { useState } from 'react';
import {
  Coffee,
  Copy,
  Check,
  FileCode,
  Terminal,
  Cpu,
  Package
} from 'lucide-react';
import { JarTriageInfo, Finding } from '../types';

interface JarTriageCardProps {
  jarInfo?: JarTriageInfo;
  filename?: string;
  findings?: Finding[];
}

export const JarTriageCard: React.FC<JarTriageCardProps> = ({
  jarInfo,
  filename = 'application.jar'
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'manifest' | 'apis' | 'binaries' | 'packages'>('manifest');
  const [copiedManifest, setCopiedManifest] = useState<boolean>(false);

  if (!jarInfo) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <Coffee className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <p className="text-sm text-slate-500 font-medium">No Java Archive (JAR) triage metadata available for this file.</p>
      </div>
    );
  }

  const {
    main_class,
    permissions,
    manifest_content = '',
    class_count = 0,
    embedded_binaries = [],
    packages = [],
    total_entries = 0,
    suspicious_apis = []
  } = jarInfo;

  const handleCopyManifest = () => {
    navigator.clipboard.writeText(manifest_content);
    setCopiedManifest(true);
    setTimeout(() => setCopiedManifest(false), 2000);
  };

  const isAllPermissions = permissions && permissions.toLowerCase().includes('all-permissions');

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between pb-6 border-b border-slate-100 gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-amber-50 text-amber-600 rounded-2xl shrink-0">
            <Coffee className="w-7 h-7" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <h3 className="text-lg font-bold text-slate-900">
                Java Archive (JAR) Deep Bytecode Triage
              </h3>
              <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                {filename}
              </span>
              {main_class && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                  Executable JAR (Main-Class)
                </span>
              )}
              {isAllPermissions && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-rose-600 text-white animate-pulse">
                  ⚠️ all-permissions Requested
                </span>
              )}
              {embedded_binaries.length > 0 && (
                <span className="text-xs px-2.5 py-0.5 rounded-full font-bold bg-purple-50 text-purple-700 border border-purple-300">
                  Embedded Native Payloads ({embedded_binaries.length})
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              JAR manifest verification, elevated sandbox permissions, class bytecode scanning for process execution &amp; reflection APIs.
            </p>
          </div>
        </div>

        {/* Quick Metrics Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Classes</span>
            <strong className="text-slate-900">{class_count}</strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Dangerous APIs</span>
            <strong className={suspicious_apis.length > 0 ? 'text-rose-600' : 'text-slate-900'}>
              {suspicious_apis.length}
            </strong>
          </div>
          <div className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-center min-w-[70px]">
            <span className="text-[10px] uppercase text-slate-400 block font-sans">Total Entries</span>
            <strong className="text-slate-900">{total_entries}</strong>
          </div>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2 overflow-x-auto text-xs font-semibold">
        <button
          onClick={() => setActiveSubTab('manifest')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'manifest'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>MANIFEST.MF &amp; Entry Points</span>
        </button>

        <button
          onClick={() => setActiveSubTab('apis')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'apis'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-rose-500" />
          <span>Dangerous Bytecode APIs ({suspicious_apis.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('binaries')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'binaries'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-purple-500" />
          <span>Embedded Native Binaries ({embedded_binaries.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('packages')}
          className={`px-3 py-1.5 rounded-xl transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeSubTab === 'packages'
              ? 'bg-slate-900 text-white'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Package className="w-3.5 h-3.5 text-amber-500" />
          <span>Class Packages ({packages.length})</span>
        </button>
      </div>

      {/* Tab 1: Manifest & Entry Points */}
      {activeSubTab === 'manifest' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-400 block font-sans">
                Main-Class Standalone Entry Point
              </span>
              <div className="font-mono text-xs font-bold text-indigo-700 bg-white p-2.5 rounded-xl border border-slate-200">
                {main_class || '<None declared in manifest>'}
              </div>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-400 block font-sans">
                Permissions Security Policy
              </span>
              <div className={`font-mono text-xs font-bold p-2.5 rounded-xl border ${
                isAllPermissions ? 'bg-rose-50 border-rose-200 text-rose-700' : 'bg-white border-slate-200 text-slate-700'
              }`}>
                {permissions || 'sandbox (default restricted)'}
              </div>
            </div>
          </div>

          {/* Raw Manifest Viewer */}
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-slate-50 text-slate-800 font-mono text-xs">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 flex items-center justify-between">
              <span className="font-bold text-slate-800">META-INF/MANIFEST.MF</span>
              <button
                onClick={handleCopyManifest}
                className="px-2.5 py-1 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-[11px] font-sans font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedManifest ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedManifest ? 'Copied' : 'Copy Manifest'}</span>
              </button>
            </div>
            <div className="p-4 max-h-[400px] overflow-y-auto space-y-1 bg-white">
              {(manifest_content || 'Manifest empty or absent.').split('\n').map((line, i) => (
                <div key={i} className="flex hover:bg-slate-50 leading-5">
                  <span className="w-8 select-none text-slate-400 text-right pr-3 shrink-0">
                    {i + 1}
                  </span>
                  <span className="whitespace-pre text-slate-800">{line || ' '}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Dangerous APIs */}
      {activeSubTab === 'apis' && (
        <div className="space-y-4">
          {suspicious_apis.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-xs text-slate-500">
              No high-risk Java API invocations (ProcessBuilder, Runtime.exec, reflection) discovered in class bytecode.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-xs text-slate-700">
                High-Risk Java API Calls in Bytecode ({suspicious_apis.length})
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {suspicious_apis.map((item, i) => (
                  <div key={i} className="p-3.5 flex items-start justify-between gap-4 hover:bg-slate-50">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-bold text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-200">
                          {item.api}
                        </span>
                        <span className="text-slate-500 text-[11px] font-sans">{item.description}</span>
                      </div>
                      <div className="text-[11px] text-slate-600 font-mono">
                        Class File: <strong className="text-slate-800">{item.class_file}</strong>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-rose-100 text-rose-800 shrink-0 font-sans">
                      Suspicious API
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Embedded Native Binaries */}
      {activeSubTab === 'binaries' && (
        <div className="space-y-4 text-xs">
          {embedded_binaries.length === 0 ? (
            <div className="p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center text-slate-500">
              No embedded native libraries (.dll, .so, .exe) bundled within the JAR archive.
            </div>
          ) : (
            <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
              <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-slate-700">
                Embedded Native Libraries &amp; Executables ({embedded_binaries.length})
              </div>
              <div className="divide-y divide-slate-100 font-mono text-xs">
                {embedded_binaries.map((b, i) => (
                  <div key={i} className="p-3 flex items-center justify-between hover:bg-slate-50">
                    <span className="text-purple-700 font-bold">{b}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 font-sans">
                      Native Dropper / Library
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Packages */}
      {activeSubTab === 'packages' && (
        <div className="space-y-4 text-xs">
          <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white">
            <div className="bg-slate-100 px-4 py-2 border-b border-slate-200 font-bold text-slate-700">
              Discovered Package Namespaces ({packages.length})
            </div>
            <div className="p-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 font-mono text-xs max-h-60 overflow-y-auto">
              {packages.map((pkg, i) => (
                <div key={i} className="p-2 bg-slate-50 rounded-xl border border-slate-200 text-slate-700 truncate">
                  {pkg}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
