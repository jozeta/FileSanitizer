import React, { useState, useRef } from 'react';
import { MapPin, FileText, Camera, Layers, ShieldAlert, ExternalLink, Link as LinkIcon } from 'lucide-react';
import { StructuredMetadata, MetadataField } from '../types';
import { GpsCoordinateBadge } from './GpsCoordinateBadge';

interface MetadataViewerProps {
  metadata?: StructuredMetadata;
}

export const MetadataViewer: React.FC<MetadataViewerProps> = ({ metadata }) => {
  const [activeTab, setActiveTab] = useState<'all' | 'general' | 'document' | 'location' | 'camera' | 'embedded'>('all');

  // Hover state for discovered URLs in metadata
  const [hoveredUrlInfo, setHoveredUrlInfo] = useState<{
    url: string;
    x: number;
    y: number;
  } | null>(null);

  const hideTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  if (!metadata || metadata.total_fields === 0) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 text-center text-slate-500 shadow-sm">
        <p className="text-sm">No metadata fields were found in this file.</p>
      </div>
    );
  }

  // Extract location fields if present for instant coordinates badge resolution
  const gpsCoordsField = metadata.location.find(f => f.name.toLowerCase().includes('gps'));
  const cityField = metadata.location.find(f => f.name.toLowerCase() === 'city')?.value;
  const countryField = metadata.location.find(f => f.name.toLowerCase() === 'country')?.value;
  const resolvedField = metadata.location.find(f => f.name.toLowerCase() === 'resolved location')?.value;
  const latField = metadata.location.find(f => f.name.toLowerCase() === 'latitude')?.value;
  const lonField = metadata.location.find(f => f.name.toLowerCase() === 'longitude')?.value;

  // Calculate actual count of embedded items (not count of property schema rows)
  const getActualEmbeddedCount = (): number => {
    let count = 0;
    for (const f of metadata.embedded) {
      const valLower = f.value.toLowerCase();
      if (valLower === '0' || valLower === 'no' || valLower === 'none') {
        continue;
      }
      const match = f.value.match(/(\d+)/);
      if (match) {
        count += parseInt(match[1], 10);
      } else if (valLower.includes('detected') || valLower.includes('yes') || valLower.includes('present')) {
        count += 1;
      }
    }
    return count;
  };

  const actualEmbeddedCount = getActualEmbeddedCount();

  const tabs = [
    { id: 'all', label: `All (${metadata.total_fields})`, icon: Layers },
    { id: 'general', label: `General (${metadata.general.length})`, icon: FileText },
    { id: 'document', label: `Document (${metadata.document.length})`, icon: FileText },
    { id: 'location', label: `Location (${metadata.location.length})`, icon: MapPin },
    { id: 'camera', label: `Camera (${metadata.camera.length})`, icon: Camera },
    { id: 'embedded', label: `Embedded (${actualEmbeddedCount})`, icon: Layers },
  ];

  const getFields = (): MetadataField[] => {
    switch (activeTab) {
      case 'general': return metadata.general;
      case 'document': return metadata.document;
      case 'location': return metadata.location;
      case 'camera': return metadata.camera;
      case 'embedded': return metadata.embedded;
      case 'all':
      default:
        return [
          ...metadata.location,
          ...metadata.document,
          ...metadata.camera,
          ...metadata.embedded,
          ...metadata.general
        ];
    }
  };

  const fields = getFields();

  const handleMouseEnterUrlIcon = (e: React.MouseEvent, url: string) => {
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current);
      hideTimeoutRef.current = null;
    }
    const rect = e.currentTarget.getBoundingClientRect();
    setHoveredUrlInfo({
      url,
      x: Math.min(rect.left, window.innerWidth - 360),
      y: rect.bottom + 8
    });
  };

  const handleMouseLeaveUrl = () => {
    hideTimeoutRef.current = setTimeout(() => {
      setHoveredUrlInfo(null);
    }, 280);
  };

  const handleMouseEnterPopover = () => {
    if (hideTimeoutRef.current) {
      clearTimeout(hideTimeoutRef.current);
      hideTimeoutRef.current = null;
    }
  };

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-slate-900 tracking-tight">
            Extracted Metadata & Privacy Analysis
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            Total {metadata.total_fields} fields inspected · {metadata.sensitive_count} sensitive fields identified
          </p>
        </div>

        {metadata.sensitive_count > 0 && (
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs font-medium">
            <ShieldAlert className="w-4 h-4 text-amber-600 shrink-0" />
            <span>Sensitive location or author details detected</span>
          </div>
        )}
      </div>

      {/* Forensic Timeline & Author Anomaly Banner */}
      {metadata.forensic_anomalies && metadata.forensic_anomalies.length > 0 && (
        <div className="mb-5 p-4 rounded-2xl bg-rose-50/80 border border-rose-200 shadow-xs space-y-2.5">
          <div className="flex items-center gap-2">
            <span className="p-1.5 bg-rose-100 text-rose-700 rounded-lg text-sm">⏱️</span>
            <div className="flex items-center gap-2">
              <span className="font-bold text-rose-900 text-xs">
                Forensic Metadata & Timestomping Anomalies Detected ({metadata.forensic_anomalies.length})
              </span>
              <span className="px-2 py-0.5 bg-rose-600 text-white rounded text-[10px] font-extrabold uppercase tracking-wider">
                Investigate
              </span>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
            {metadata.forensic_anomalies.map((anom, idx) => (
              <div key={idx} className="p-2.5 bg-white border border-rose-200/80 rounded-xl">
                <span className="font-bold text-rose-950 block text-[11px] mb-0.5">{anom.title}</span>
                <span className="text-slate-600 font-mono text-[10px] break-all">{anom.details}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* GPS Geolocation Banner (if GPS is present) */}
      {gpsCoordsField && (
        <div className="mb-5 p-4 rounded-2xl bg-blue-50/80 border border-blue-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-600 text-white shrink-0 shadow-sm">
              <MapPin className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-mono uppercase tracking-wider text-blue-900 font-bold flex items-center gap-1.5">
                <span>GPS Geographic Coordinates Identified</span>
              </div>
              <div className="text-xs text-blue-800 font-medium mt-0.5">
                {resolvedField || (cityField && countryField ? `${cityField}, ${countryField}` : 'Hover over coordinates to reveal resolved city and country')}
              </div>
            </div>
          </div>
          <div>
            <GpsCoordinateBadge
              latitude={latField}
              longitude={lonField}
              readableCoordinates={gpsCoordsField.value}
              initialCity={cityField}
              initialCountry={countryField}
              locationName={resolvedField}
            />
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex flex-wrap gap-1.5 pb-4 mb-4 border-b border-slate-100">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                isActive
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'bg-slate-50 hover:bg-slate-100 text-slate-600'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Fields Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-100 text-slate-400 font-mono">
              <th className="pb-2.5 font-normal">Property</th>
              <th className="pb-2.5 font-normal">Value</th>
              <th className="pb-2.5 font-normal">Privacy Category</th>
              <th className="pb-2.5 font-normal text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-mono">
            {fields.map((field, idx) => {
              const isGpsCoord = field.name.toLowerCase().includes('gps coordinates') || field.name === 'GPS Coordinates';
              const urlMatch = !isGpsCoord ? field.value.match(/https?:\/\/[^\s"'<>]+|www\.[^\s"'<>]+/i) : null;
              const detectedUrl = urlMatch ? urlMatch[0] : null;

              // Check if field is a cryptographic hash (MD5, SHA1, SHA256)
              const nameLower = field.name.toLowerCase();
              const isHashField =
                nameLower === 'md5' ||
                nameLower === 'sha1' ||
                nameLower === 'sha256' ||
                nameLower === 'sha-256' ||
                nameLower === 'sha-1' ||
                (nameLower.includes('hash') && /^[a-fA-F0-9]{32,64}$/.test(field.value.trim()));

              return (
                <tr key={idx} className={`hover:bg-slate-50/80 transition-colors ${field.is_sensitive ? 'bg-amber-50/30' : ''}`}>
                  <td className="py-2.5 font-medium text-slate-800 pr-4">
                    {field.name}
                  </td>
                  <td className="py-2.5 text-slate-600 pr-4 break-all max-w-xs sm:max-w-md font-sans">
                    {isGpsCoord ? (
                      <GpsCoordinateBadge
                        latitude={latField}
                        longitude={lonField}
                        readableCoordinates={field.value}
                        initialCity={cityField}
                        initialCountry={countryField}
                        locationName={resolvedField}
                      />
                    ) : detectedUrl ? (
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-slate-800 font-mono">{field.value}</span>
                        <button
                          type="button"
                          onMouseEnter={(e) => handleMouseEnterUrlIcon(e, detectedUrl)}
                          onMouseLeave={handleMouseLeaveUrl}
                          className="p-1 text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded-md transition-colors cursor-pointer inline-flex items-center gap-1 text-[11px] font-sans font-medium"
                          title="Inspect detected URL"
                        >
                          <LinkIcon className="w-3.5 h-3.5 text-indigo-600" />
                          <span className="text-[10px]">Inspect</span>
                        </button>
                      </div>
                    ) : isHashField ? (
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-slate-800 text-[11px] select-all">{field.value}</span>
                        <a
                          href={`https://www.virustotal.com/gui/file/${field.value.trim()}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[10px] bg-indigo-50 hover:bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-md border border-indigo-200/80 font-sans font-medium transition-colors"
                        >
                          <ExternalLink className="w-2.5 h-2.5" />
                          <span>VirusTotal</span>
                        </a>
                      </div>
                    ) : (
                      field.value
                    )}
                  </td>
                  <td className="py-2.5 text-slate-400 uppercase text-[10px]">
                    {field.category}
                  </td>
                  <td className="py-2.5 text-right">
                    {field.is_sensitive ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 font-bold text-[10px]">
                        SENSITIVE
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-slate-400 text-[10px]">
                        Standard
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Standalone URL Hover Popover that doesn't disappear prematurely and allows clicking links */}
      {hoveredUrlInfo && (
        <div
          onMouseEnter={handleMouseEnterPopover}
          onMouseLeave={handleMouseLeaveUrl}
          style={{
            position: 'fixed',
            left: hoveredUrlInfo.x,
            top: hoveredUrlInfo.y,
            zIndex: 9999,
          }}
          className="w-80 bg-white text-slate-800 rounded-2xl p-4 shadow-2xl border border-slate-200 animate-modal-fade pointer-events-auto"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-indigo-600 font-bold flex items-center gap-1.5">
              <span>🌐</span> Detected URL in Metadata
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
              Inspection
            </span>
          </div>
          <p className="text-xs font-mono text-slate-800 break-all bg-slate-50 p-2.5 rounded-xl border border-slate-200 mb-3">
            {hoveredUrlInfo.url}
          </p>
          <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-100 text-xs">
            <span className="text-slate-400 text-[11px]">External link reference</span>
            <a
              href={`https://www.virustotal.com/gui/search/${encodeURIComponent(hoveredUrlInfo.url)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-indigo-600 hover:text-indigo-800 font-medium inline-flex items-center gap-1 text-xs hover:underline"
            >
              <span>Scan on VirusTotal</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      )}
    </div>
  );
};
