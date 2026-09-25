import React, { useState } from 'react';
import { Sliders, AlertTriangle, ArrowRight, Zap } from 'lucide-react';
import { SanitizationOptions } from '../types';

interface SanitizationPanelProps {
  category: string;
  isProcessing: boolean;
  onSanitize: (profile: string, customOptions?: SanitizationOptions) => void;
  suggestedProfile?: string;
  isMalicious?: boolean;
}

export const SanitizationPanel: React.FC<SanitizationPanelProps> = ({
  category,
  isProcessing,
  onSanitize,
  suggestedProfile = 'privacy',
  isMalicious = false
}) => {
  const [selectedProfile, setSelectedProfile] = useState<string>(suggestedProfile);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Granular options state
  const [options, setOptions] = useState<SanitizationOptions>({
    profile: suggestedProfile,
    remove_metadata: true,
    remove_gps: true,
    remove_author: true,
    remove_timestamps: true,
    remove_comments: true,
    remove_embedded_files: true,
    remove_macros: true,
    remove_javascript: true,
    remove_external_links: true,
    remove_hyperlinks: false,
    reencode_image: true,
    flatten_image: false,
    convert_to_jpg: false,
    convert_to_png: false,
    flatten_document: false,
    rasterize_pages: selectedProfile === 'maximum',
    convert_to_pdf: false,
    strip_active_content: true,
    strip_external_resources: true,
  });

  const handleProfileSelect = (prof: string) => {
    setSelectedProfile(prof);
    if (prof === 'minimal') {
      setOptions(prev => ({
        ...prev,
        profile: prof,
        remove_metadata: true,
        remove_gps: true,
        remove_author: true,
        remove_timestamps: false,
        remove_comments: false,
        remove_embedded_files: false,
        remove_macros: false,
        remove_javascript: false,
        remove_external_links: false,
        rasterize_pages: false,
        flatten_document: false
      }));
    } else if (prof === 'privacy') {
      setOptions(prev => ({
        ...prev,
        profile: prof,
        remove_metadata: true,
        remove_gps: true,
        remove_author: true,
        remove_timestamps: true,
        remove_comments: true,
        remove_embedded_files: false,
        remove_macros: false,
        remove_javascript: false,
        remove_external_links: false,
        rasterize_pages: false,
        flatten_document: false
      }));
    } else if (prof === 'security') {
      setOptions(prev => ({
        ...prev,
        profile: prof,
        remove_metadata: true,
        remove_gps: true,
        remove_author: true,
        remove_timestamps: true,
        remove_comments: true,
        remove_embedded_files: true,
        remove_macros: true,
        remove_javascript: true,
        remove_external_links: true,
        remove_hyperlinks: true,
        rasterize_pages: false,
        flatten_document: true
      }));
    } else if (prof === 'maximum') {
      setOptions(prev => ({
        ...prev,
        profile: prof,
        remove_metadata: true,
        remove_gps: true,
        remove_author: true,
        remove_timestamps: true,
        remove_comments: true,
        remove_embedded_files: true,
        remove_macros: true,
        remove_javascript: true,
        remove_external_links: true,
        remove_hyperlinks: true,
        rasterize_pages: true,
        flatten_document: true,
        flatten_image: true,
        reencode_image: true
      }));
    }
  };

  const handleToggle = (key: keyof SanitizationOptions) => {
    setOptions(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const profiles = [
    {
      id: 'minimal',
      title: 'Minimal',
      badge: 'Light',
      desc: 'Clears obvious metadata tags only while leaving document structure untouched.',
    },
    {
      id: 'privacy',
      title: 'Privacy',
      badge: 'Recommended',
      desc: 'Strips EXIF, GPS location, author identities, timestamps, and comments.',
    },
    {
      id: 'security',
      title: 'Security',
      badge: 'Standard',
      desc: 'Purges active macros, JavaScript, external templates, embedded binaries, and dangerous actions.',
    },
    {
      id: 'maximum',
      title: 'Maximum Sanitization',
      badge: 'Deep CDR',
      desc: 'Aggressive Content Disarm & Reconstruction: renders pages to pure pixel images and reconstructs a brand-new container.',
    },
  ];

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-lg font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Zap className="w-5 h-5 text-blue-600" />
            <span>Select Sanitization Profile & Options</span>
          </h3>
          <p className="text-xs text-slate-500">
            Choose a preset profile or fine-tune disarming parameters for this {category.toUpperCase()} file.
          </p>
        </div>

        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-xs font-medium text-slate-600 hover:text-slate-900 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors self-start sm:self-auto cursor-pointer"
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>{showAdvanced ? 'Hide Fine-Grained Controls' : 'Fine-Grained Controls'}</span>
        </button>
      </div>

      {/* Profiles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-6">
        {profiles.map((p) => {
          const isSelected = selectedProfile === p.id;
          const isSuggested = suggestedProfile === p.id;

          return (
            <div
              key={p.id}
              onClick={() => handleProfileSelect(p.id)}
              className={`p-4 rounded-2xl border-2 transition-all cursor-pointer relative ${
                isSelected
                  ? 'border-blue-600 bg-blue-50/40 shadow-sm'
                  : 'border-slate-200 hover:border-slate-300 bg-slate-50/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-slate-900">{p.title}</span>
                  {isSuggested && (
                    <span className="px-2 py-0.5 bg-blue-100 text-blue-800 text-[10px] font-bold rounded-full uppercase tracking-wider">
                      Suggested
                    </span>
                  )}
                </div>
                <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                  isSelected ? 'border-blue-600 bg-blue-600 text-white' : 'border-slate-300'
                }`}>
                  {isSelected && <div className="w-1.5 h-1.5 bg-white rounded-full" />}
                </div>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed font-normal">
                {p.desc}
              </p>
            </div>
          );
        })}
      </div>

      {/* Maximum Sanitization Consequence Warning */}
      {selectedProfile === 'maximum' && (
        <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-2xl text-amber-900 mb-6">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <span className="font-bold block text-amber-950">Content Disarm & Reconstruction (CDR) Notice:</span>
              <p className="leading-relaxed">
                Maximum Sanitization converts complex structures, active scripts, and vector formats into rendered raster pixels before building a completely new document.
                {category === 'pdf' && ' Searchable text, form fields, and vector fidelity will be flattened into images.'}
                {category === 'image' && ' Transparency channels will be flattened onto a solid background and re-encoded.'}
                {category === 'office' && ' Macros and external templates will be completely eradicated.'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Advanced Fine-Grained Controls */}
      {showAdvanced && (
        <div className="mb-6 p-5 bg-slate-50 rounded-2xl border border-slate-200">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 mb-3">
            Applicable Sanitization Toggles for {category.toUpperCase()}:
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            {/* General & Metadata */}
            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_metadata}
                onChange={() => handleToggle('remove_metadata')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove All Metadata</span>
            </label>

            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_gps}
                onChange={() => handleToggle('remove_gps')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove GPS Coordinates</span>
            </label>

            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_author}
                onChange={() => handleToggle('remove_author')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove Author Information</span>
            </label>

            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_comments}
                onChange={() => handleToggle('remove_comments')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove Comments</span>
            </label>

            {/* Active Content & Security */}
            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_macros}
                onChange={() => handleToggle('remove_macros')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove VBA Macros</span>
            </label>

            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_javascript}
                onChange={() => handleToggle('remove_javascript')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove JavaScript</span>
            </label>

            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_embedded_files}
                onChange={() => handleToggle('remove_embedded_files')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove Embedded Files & OLE</span>
            </label>

            <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={options.remove_external_links}
                onChange={() => handleToggle('remove_external_links')}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="font-medium text-slate-800">Remove External Links / URIs</span>
            </label>

            {/* Category specifics */}
            {category === 'pdf' && (
              <>
                <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.flatten_document}
                    onChange={() => handleToggle('flatten_document')}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="font-medium text-slate-800">Flatten Forms & Annotations</span>
                </label>

                <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.rasterize_pages}
                    onChange={() => handleToggle('rasterize_pages')}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="font-medium text-slate-800 font-bold text-blue-700">Rasterize PDF Pages (Image PDF CDR)</span>
                </label>
              </>
            )}

            {category === 'image' && (
              <>
                <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.reencode_image}
                    onChange={() => handleToggle('reencode_image')}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="font-medium text-slate-800">Re-encode Image Pixels</span>
                </label>

                <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.flatten_image}
                    onChange={() => handleToggle('flatten_image')}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="font-medium text-slate-800">Flatten Transparency</span>
                </label>

                <label className="flex items-center gap-2.5 p-2 bg-white rounded-xl border border-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.convert_to_png}
                    onChange={() => handleToggle('convert_to_png')}
                    className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="font-medium text-slate-800">Convert to PNG</span>
                </label>
              </>
            )}
          </div>
        </div>
      )}

      {/* Action Trigger */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 border-t border-slate-100">
        <div className="text-xs text-slate-500">
          * Original file will remain isolated and untouched in its temporary workspace.
        </div>

        <button
          onClick={() => onSanitize(selectedProfile, showAdvanced ? options : undefined)}
          disabled={isProcessing || isMalicious}
          className={`w-full sm:w-auto px-8 py-3.5 font-semibold text-sm rounded-xl shadow-sm transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer ${
            isMalicious
              ? 'bg-slate-300 text-slate-500 cursor-not-allowed'
              : 'bg-slate-900 hover:bg-blue-600 text-white'
          }`}
        >
          <span>{isProcessing ? 'Disarming & Reconstructing...' : 'Disarm & Sanitize File'}</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
