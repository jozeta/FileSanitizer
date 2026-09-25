import React, { useState } from 'react';
import { MapPin, FileText, Camera, Layers, ShieldAlert } from 'lucide-react';
import { StructuredMetadata, MetadataField } from '../types';

interface MetadataViewerProps {
  metadata?: StructuredMetadata;
}

export const MetadataViewer: React.FC<MetadataViewerProps> = ({ metadata }) => {
  const [activeTab, setActiveTab] = useState<'all' | 'general' | 'document' | 'location' | 'camera' | 'embedded'>('all');

  if (!metadata || metadata.total_fields === 0) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-8 text-center text-slate-500 shadow-sm">
        <p className="text-sm">No metadata fields were found in this file.</p>
      </div>
    );
  }

  const tabs = [
    { id: 'all', label: `All (${metadata.total_fields})`, icon: Layers },
    { id: 'general', label: `General (${metadata.general.length})`, icon: FileText },
    { id: 'document', label: `Document (${metadata.document.length})`, icon: FileText },
    { id: 'location', label: `Location (${metadata.location.length})`, icon: MapPin },
    { id: 'camera', label: `Camera (${metadata.camera.length})`, icon: Camera },
    { id: 'embedded', label: `Embedded (${metadata.embedded.length})`, icon: Layers },
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
          ...metadata.location, // Show location first if present
          ...metadata.document,
          ...metadata.camera,
          ...metadata.embedded,
          ...metadata.general
        ];
    }
  };

  const fields = getFields();

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-bold text-slate-900 tracking-tight">
            Extracted Metadata & Privacy Analysis
          </h3>
          <p className="text-xs text-slate-500">
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
              <th className="pb-2 font-normal">Property</th>
              <th className="pb-2 font-normal">Value</th>
              <th className="pb-2 font-normal">Privacy Category</th>
              <th className="pb-2 font-normal text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-mono">
            {fields.map((field, idx) => (
              <tr key={idx} className={`hover:bg-slate-50/80 transition-colors ${field.is_sensitive ? 'bg-amber-50/30' : ''}`}>
                <td className="py-2.5 font-medium text-slate-800 pr-4">
                  {field.name}
                </td>
                <td className="py-2.5 text-slate-600 pr-4 break-all max-w-xs sm:max-w-md font-sans">
                  {field.value}
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
