import React, { useState, useEffect } from 'react';
import { Sliders, AlertTriangle, ArrowRight, Zap, Download, Sparkles } from 'lucide-react';
import { SanitizationOptions, CdrFormatPolicy } from '../types';

export type OutputFormatType = 'original' | 'pdf' | 'png' | 'jpg';

interface FormatOption {
  id: OutputFormatType;
  title: string;
  badge: string;
  badgeBg: string;
  badgeText: string;
  desc: string;
  whatHappens: string;
}

const getCategoryFormatConfig = (category: string): { options: FormatOption[]; lockedNotice?: string } => {
  const cat = (category || '').toLowerCase();

  if (cat === 'executable' || cat === 'binary') {
    return {
      options: [
        {
          id: 'original',
          title: 'Sanitized Binary Container',
          badge: '.EXE / .BIN',
          badgeBg: 'bg-slate-100',
          badgeText: 'text-slate-800',
          desc: 'Quarantines executable payload, clears filesystem execute bits (0o644), and neutralizes runtime triggers.',
          whatHappens: 'The executable binary will be disarmed and quarantined. Active execution flags are permanently removed. Direct conversion to images or documents is not applicable.'
        }
      ],
      lockedNotice: 'Executable binaries cannot be converted to images or text documents; sanitization hardens and neutralizes the native executable payload.'
    };
  }

  if (cat === 'archive') {
    return {
      options: [
        {
          id: 'original',
          title: 'Sanitized ZIP Archive',
          badge: '.ZIP',
          badgeBg: 'bg-amber-100',
          badgeText: 'text-amber-800',
          desc: 'Extracts archive members, purges dangerous executables (.exe, .scr, .bat) and directory traversal (../), and rebuilds clean ZIP.',
          whatHappens: 'Dangerous payloads, script attachments, and zip slip paths are purged, producing a verified safe ZIP container.'
        }
      ],
      lockedNotice: 'Archive containers cannot be converted into single images or documents; sanitization cleans and rebuilds the compressed ZIP archive.'
    };
  }

  if (cat === 'email') {
    return {
      options: [
        {
          id: 'original',
          title: 'Disarmed Email Message',
          badge: '.EML',
          badgeBg: 'bg-indigo-100',
          badgeText: 'text-indigo-800',
          desc: 'Removes web beacons, tracking pixels, scripts, and neutralizes dangerous attachments into quarantine warnings.',
          whatHappens: 'Returns a clean RFC 822 email message safe to open in any client with tracking bugs and malware attachments neutralized.'
        },
        {
          id: 'pdf',
          title: 'Download as Clean PDF',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Converts email headers, text body, and message formatting into a standardized static PDF document.',
          whatHappens: 'Flattens the entire email into an unmodifiable, printable PDF document, permanently destroying all active script execution vectors.'
        }
      ]
    };
  }

  if (cat === 'office') {
    return {
      options: [
        {
          id: 'original',
          title: 'Clean Office Document',
          badge: '.DOCX / .XLSX / .PPTX',
          badgeBg: 'bg-blue-100',
          badgeText: 'text-blue-800',
          desc: 'Purges VBA macros (vbaProject.bin), OLE embeddings, and external relationship injections while preserving document layout.',
          whatHappens: 'The document remains editable in Word/Excel/PowerPoint, but all macro code, embedded executables, and tracking templates are completely excised.'
        },
        {
          id: 'pdf',
          title: 'Download as Hardened PDF',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Converts the Office document into a hardened, standardized PDF document.',
          whatHappens: 'Exports content into a clean PDF document, completely bypassing Microsoft Office macro runtime engines.'
        }
      ]
    };
  }

  if (cat === 'pdf') {
    return {
      options: [
        {
          id: 'original',
          title: 'Sanitized Vector PDF',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Disarms JavaScript, /Launch actions, embedded attachments, and metadata while keeping searchable vector text and crisp layout.',
          whatHappens: 'The PDF is disarmed by removing all interactive script actions, annotations, and hidden streams while preserving vector rendering.'
        },
        {
          id: 'png',
          title: 'Flatten Pages to Raster PNG',
          badge: '.PNG',
          badgeBg: 'bg-emerald-100',
          badgeText: 'text-emerald-700',
          desc: 'Deep CDR: Renders all document pages into static high-resolution pixel images, eliminating all vector/code attack vectors.',
          whatHappens: 'Every page is rasterized into a pure PNG image. All zero-day stream exploits, embedded fonts, and script vectors are 100% neutralized.'
        }
      ]
    };
  }

  if (cat === 'image') {
    return {
      options: [
        {
          id: 'original',
          title: 'Original Image Format',
          badge: 'SAME',
          badgeBg: 'bg-slate-100',
          badgeText: 'text-slate-800',
          desc: 'Strips EXIF, GPS location, device serial numbers, and metadata while keeping the original image container.',
          whatHappens: 'All privacy-sensitive EXIF tags and hidden metadata packets are purged from the image file.'
        },
        {
          id: 'png',
          title: 'Download as Lossless PNG',
          badge: '.PNG',
          badgeBg: 'bg-emerald-100',
          badgeText: 'text-emerald-700',
          desc: 'Re-encodes image into a clean, uncompressed PNG container, stripping steganographic comments and metadata.',
          whatHappens: 'The image is re-encoded into standardized PNG pixel data with fresh clean headers.'
        },
        {
          id: 'jpg',
          title: 'Download as Web JPEG',
          badge: '.JPG',
          badgeBg: 'bg-amber-100',
          badgeText: 'text-amber-800',
          desc: 'Compresses and flattens transparency onto a solid white background, removing all hidden EXIF payloads.',
          whatHappens: 'The image is converted to standard JPEG format, flattening alpha channels and stripping metadata.'
        },
        {
          id: 'pdf',
          title: 'Download as Single-Page PDF',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Wraps the sanitized image into a clean, standardized PDF document.',
          whatHappens: 'Packages the sanitized image into an unmodifiable PDF document.'
        }
      ]
    };
  }

  if (cat === 'text') {
    return {
      options: [
        {
          id: 'original',
          title: 'Sanitized Text Container',
          badge: 'TEXT',
          badgeBg: 'bg-slate-100',
          badgeText: 'text-slate-800',
          desc: 'Removes invisible Unicode characters, bi-di override exploits, zero-width spaces, and spreadsheet formula injection (=cmd).',
          whatHappens: 'The text/csv file is cleaned of hidden control codes and formula injection strings.'
        },
        {
          id: 'pdf',
          title: 'Download as Formatted PDF',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Formats text lines onto standard PDF pages with Courier typography and clean headers.',
          whatHappens: 'The text content is laid out onto standard PDF pages.'
        }
      ]
    };
  }

  if (cat === 'svg') {
    return {
      options: [
        {
          id: 'original',
          title: 'Sanitized Vector SVG',
          badge: '.SVG',
          badgeBg: 'bg-orange-100',
          badgeText: 'text-orange-800',
          desc: 'Removes <script> tags, inline event handlers (onload, onclick), XXE entities, and foreign objects while preserving vector markup.',
          whatHappens: 'The SVG is disarmed of all scriptable DOM triggers while keeping scalable vector artwork.'
        },
        {
          id: 'png',
          title: 'Rasterize to Static PNG',
          badge: '.PNG',
          badgeBg: 'bg-emerald-100',
          badgeText: 'text-emerald-700',
          desc: 'Converts vector graphics to flat PNG pixels, permanently removing all XML script execution vectors.',
          whatHappens: 'The vector graphic is rendered to an unmodifiable PNG image.'
        },
        {
          id: 'pdf',
          title: 'Convert to Secure PDF',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Converts vector SVG graphics into a secure standalone PDF document.',
          whatHappens: 'The SVG is rendered into a clean vector PDF.'
        }
      ]
    };
  }

  if (cat === 'script') {
    return {
      options: [
        {
          id: 'original',
          title: 'Disarmed Script Container',
          badge: 'SCRIPT',
          badgeBg: 'bg-emerald-100',
          badgeText: 'text-emerald-800',
          desc: 'Disarms dangerous dynamic execution hooks (IEX, eval, curl|sh, certutil), defangs URLs/IPs, enforces read-only non-executable permissions (0o644), and prepends FileSanitizer security notice.',
          whatHappens: 'Dangerous execution patterns and command injection hooks are neutralized while preserving readable script logic.'
        },
        {
          id: 'pdf',
          title: 'Hardened Vector PDF Review Document',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Converts disarmed script into a numbered, read-only PDF report with syntax watermarking, completely eliminating execution risk.',
          whatHappens: 'Renders the disarmed script into a multi-page, non-executable vector PDF document for safe forensic code review.'
        }
      ]
    };
  }

  if (cat === 'apk') {
    return {
      options: [
        {
          id: 'original',
          title: 'Disarmed Android Package Container',
          badge: '.APK',
          badgeBg: 'bg-emerald-100',
          badgeText: 'text-emerald-800',
          desc: 'Neutralizes dangerous permissions (SMS, Overlay, Camera), defangs C2 endpoints, disables debuggable mode, and purges executable assets.',
          whatHappens: 'Produces a disarmed APK container with all dangerous runtime permissions stripped and active network vectors neutralized.'
        },
        {
          id: 'pdf',
          title: 'Download as Forensic Dossier (PDF)',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Compiles manifest metadata, permissions matrix, and DEX security findings into an unmodifiable, static PDF review report.',
          whatHappens: 'Permanently converts mobile application bytecode and manifest data into a clean, unmodifiable PDF document.'
        }
      ]
    };
  }

  if (cat === 'java') {
    return {
      options: [
        {
          id: 'original',
          title: 'Sanitized Java Container',
          badge: '.JAVA / .JAR',
          badgeBg: 'bg-amber-100',
          badgeText: 'text-amber-800',
          desc: 'Disarms Runtime.exec, ProcessBuilder, unmanaged memory (sun.misc.Unsafe), dynamic reflection, and clears executable flags.',
          whatHappens: 'Removes dangerous JVM execution hooks, dynamic loaders, and embedded native libraries, producing a disarmed Java container.'
        },
        {
          id: 'pdf',
          title: 'Download as Review Dossier (PDF)',
          badge: '.PDF',
          badgeBg: 'bg-rose-100',
          badgeText: 'text-rose-700',
          desc: 'Compiles Java source code, bytecode constant pool details, and security findings into a standardized static PDF report.',
          whatHappens: 'Exports code and forensic details onto clean PDF pages, eliminating all JVM bytecode execution vectors.'
        }
      ]
    };
  }

  // Default / HTML / Generic
  return {
    options: [
      {
        id: 'original',
        title: 'Original Disarmed Format',
        badge: 'NATIVE',
        badgeBg: 'bg-slate-100',
        badgeText: 'text-slate-800',
        desc: 'Cleans active scripts, dangerous HTML tags, and metadata while preserving native structure.',
        whatHappens: 'The file will be disarmed and returned in its original format with active threats removed.'
      }
    ]
  };
};

interface SanitizationPanelProps {
  category: string;
  isProcessing: boolean;
  onSanitize: (profile: string, customOptions?: SanitizationOptions) => void;
  suggestedProfile?: string;
  isMalicious?: boolean;
  isCompleted?: boolean;
  onDownload?: () => void;
  cdrPolicy?: CdrFormatPolicy;
}

// Interactive Info Popover Component for Sanitization Options
const InfoPopover: React.FC<{ title: string; content: string }> = ({ title, content }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const timeoutRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleMouseEnter = (e: React.MouseEvent) => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    const rect = e.currentTarget.getBoundingClientRect();
    setPos({
      x: Math.max(16, Math.min(rect.left - 100, window.innerWidth - 300)),
      y: rect.bottom + 6
    });
    setIsOpen(true);
  };

  const handleMouseLeave = () => {
    timeoutRef.current = setTimeout(() => setIsOpen(false), 200);
  };

  return (
    <span className="inline-flex items-center ml-1.5" onClick={(e) => e.stopPropagation()}>
      <span
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className="w-4 h-4 rounded-full bg-slate-100 hover:bg-indigo-100 text-slate-500 hover:text-indigo-600 flex items-center justify-center text-[10px] font-bold border border-slate-300 cursor-help transition-colors select-none"
      >
        i
      </span>
      {isOpen && pos && (
        <span
          onMouseEnter={() => { if (timeoutRef.current) clearTimeout(timeoutRef.current); }}
          onMouseLeave={handleMouseLeave}
          style={{ position: 'fixed', left: pos.x, top: pos.y, zIndex: 9999 }}
          className="w-72 bg-white text-slate-800 text-xs p-3.5 rounded-2xl shadow-2xl border border-slate-200 animate-modal-fade pointer-events-auto font-normal text-left leading-relaxed block"
        >
          <strong className="block text-indigo-600 font-bold mb-1 text-[11px] uppercase tracking-wider">
            {title}
          </strong>
          <span className="text-slate-600 block text-xs">{content}</span>
        </span>
      )}
    </span>
  );
};

export const SanitizationPanel: React.FC<SanitizationPanelProps> = ({
  category,
  isProcessing,
  onSanitize,
  suggestedProfile = 'privacy',
  isMalicious = false,
  isCompleted = false,
  onDownload,
  cdrPolicy
}) => {
  const [selectedProfile, setSelectedProfile] = useState<string>(suggestedProfile);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [outputFormat, setOutputFormat] = useState<OutputFormatType>('original');

  const baseConfig = getCategoryFormatConfig(category);
  // Filter formats according to policy if policy defines allowed_output_formats
  const allowedOutputFmts = cdrPolicy?.allowed_output_formats || [];
  const filteredOptions = allowedOutputFmts.length > 0
    ? baseConfig.options.filter(o => allowedOutputFmts.includes(o.id))
    : baseConfig.options;
  const formatConfig = {
    ...baseConfig,
    options: filteredOptions.length > 0 ? filteredOptions : baseConfig.options
  };
  const currentOption = formatConfig.options.find(o => o.id === outputFormat) || formatConfig.options[0];

  useEffect(() => {
    const validIds = formatConfig.options.map(o => o.id);
    if (!validIds.includes(outputFormat)) {
      setOutputFormat('original');
      setOptions(prev => ({
        ...prev,
        convert_to_pdf: false,
        convert_to_png: false,
        convert_to_jpg: false,
      }));
    }
  }, [category]);

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

  const handleFormatSelect = (fmt: OutputFormatType) => {
    setOutputFormat(fmt);
    setOptions(prev => ({
      ...prev,
      convert_to_pdf: fmt === 'pdf',
      convert_to_png: fmt === 'png',
      convert_to_jpg: fmt === 'jpg',
    }));
  };

  const handleProfileSelect = (prof: string) => {
    setSelectedProfile(prof);
    const isPdf = outputFormat === 'pdf';
    const isPng = outputFormat === 'png';
    const isJpg = outputFormat === 'jpg';

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
        flatten_document: false,
        convert_to_pdf: isPdf,
        convert_to_png: isPng,
        convert_to_jpg: isJpg
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
        flatten_document: false,
        convert_to_pdf: isPdf,
        convert_to_png: isPng,
        convert_to_jpg: isJpg
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
        flatten_document: true,
        convert_to_pdf: isPdf,
        convert_to_png: isPng,
        convert_to_jpg: isJpg
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
        reencode_image: true,
        convert_to_pdf: isPdf,
        convert_to_png: isPng,
        convert_to_jpg: isJpg
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
      infoTitle: 'Minimal Disarming',
      infoDetails: 'Removes visible author/title properties while preserving layout, fonts, and interactive elements.'
    },
    {
      id: 'privacy',
      title: 'Privacy',
      badge: 'Recommended',
      desc: 'Strips EXIF, GPS location, author identities, timestamps, and comments.',
      infoTitle: 'Privacy Sanitization',
      infoDetails: 'Purges EXIF camera metadata, embedded GPS coordinates, author names, contributor tags, creation/edit timestamps, and reviewer notes.'
    },
    {
      id: 'security',
      title: 'Security',
      badge: 'Standard',
      desc: 'Purges active macros, JavaScript, external templates, embedded binaries, and dangerous actions.',
      infoTitle: 'Security Hardening',
      infoDetails: 'Neutralizes active VBA macros, executable JavaScript actions, embedded OLE packages, external hyperlinks, and remote tracking templates.'
    },
    {
      id: 'maximum',
      title: 'Maximum Sanitization',
      badge: 'Deep CDR',
      desc: 'Aggressive Content Disarm & Reconstruction: renders pages to pure pixel images and reconstructs a brand-new container.',
      infoTitle: 'Deep CDR Reconstruction',
      infoDetails: 'Performs full rasterization: renders vector pages and layout into pure pixels, destroying all active stream exploits and zero-day payloads.'
    },
  ];

  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-lg font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Zap className="w-5 h-5 text-indigo-600" />
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
                  ? 'border-indigo-600 bg-indigo-50/40 shadow-sm'
                  : 'border-slate-200 hover:border-slate-300 bg-slate-50/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-sm text-slate-900">{p.title}</span>
                  <InfoPopover title={p.infoTitle} content={p.infoDetails} />
                  {isSuggested && (
                    <span className="ml-1 px-2 py-0.5 bg-indigo-100 text-indigo-800 text-[10px] font-bold rounded-full uppercase tracking-wider">
                      Suggested
                    </span>
                  )}
                </div>
                <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                  isSelected ? 'border-indigo-600 bg-indigo-600 text-white' : 'border-slate-300'
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
            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_metadata}
                  onChange={() => handleToggle('remove_metadata')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove All Metadata</span>
              </div>
              <InfoPopover title="Metadata Purging" content="Wipes EXIF, IPTC, XMP, PDF /Info dictionary, and Office Core/App/Custom XML properties." />
            </label>

            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_gps}
                  onChange={() => handleToggle('remove_gps')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove GPS Coordinates</span>
              </div>
              <InfoPopover title="GPS Location Purging" content="Strips GPSLatitude, GPSLongitude, GPSTimestamp, and geographic geolocation tags from image and document headers." />
            </label>

            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_author}
                  onChange={() => handleToggle('remove_author')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove Author Information</span>
              </div>
              <InfoPopover title="Author Identity Purging" content="Removes Author, Creator, LastModifiedBy, Contributor, and Manager identity metadata fields." />
            </label>

            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_comments}
                  onChange={() => handleToggle('remove_comments')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove Comments</span>
              </div>
              <InfoPopover title="Comments & Annotations" content="Strips reviewer margin annotations, editorial comments, change tracking history, and revision marks." />
            </label>

            {/* Active Content & Security */}
            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_macros}
                  onChange={() => handleToggle('remove_macros')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove VBA Macros</span>
              </div>
              <InfoPopover title="VBA Macro Eradication" content="Completely strips vbaProject.bin, macro code streams, UserForms, and AutoOpen/Document_Open execution triggers." />
            </label>

            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_javascript}
                  onChange={() => handleToggle('remove_javascript')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove JavaScript</span>
              </div>
              <InfoPopover title="JavaScript Action Purging" content="Removes PDF /JS and /JavaScript action streams, script dictionaries, and dynamic auto-run hooks." />
            </label>

            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_embedded_files}
                  onChange={() => handleToggle('remove_embedded_files')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove Embedded Files & OLE</span>
              </div>
              <InfoPopover title="Embedded Files & OLE Objects" content="Extracts or removes embedded child documents, archive attachments, and OLE payload objects nested in streams." />
            </label>

            <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={options.remove_external_links}
                  onChange={() => handleToggle('remove_external_links')}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="font-medium text-slate-800">Remove External Links / URIs</span>
              </div>
              <InfoPopover title="External Link Disarming" content="Removes clickable external web hyperlinks and remote URI actions to eliminate phishing, tracking beacons, and exploit triggers." />
            </label>

            {/* Category specifics */}
            {category === 'pdf' && (
              <>
                <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={options.flatten_document}
                      onChange={() => handleToggle('flatten_document')}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="font-medium text-slate-800">Flatten Forms & Annotations</span>
                  </div>
                  <InfoPopover title="Form Flattening" content="Bakes interactive AcroForm fields, digital signatures, and PDF annotations into static background graphics." />
                </label>

                <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={options.rasterize_pages}
                      onChange={() => handleToggle('rasterize_pages')}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="font-medium text-indigo-900 font-bold">Rasterize PDF Pages (Image PDF CDR)</span>
                  </div>
                  <InfoPopover title="Pixel Rasterization" content="Converts all vector PDF pages into high-resolution images, completely destroying all potential structural exploits." />
                </label>
              </>
            )}

            {category === 'image' && (
              <>
                <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={options.reencode_image}
                      onChange={() => handleToggle('reencode_image')}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="font-medium text-slate-800">Re-encode Image Pixels</span>
                  </div>
                  <InfoPopover title="Pixel Re-encoding" content="Decompresses and recompresses raw pixels to sanitize hidden steganographic payload data." />
                </label>

                <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={options.flatten_image}
                      onChange={() => handleToggle('flatten_image')}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="font-medium text-slate-800">Flatten Transparency</span>
                  </div>
                  <InfoPopover title="Alpha Flattening" content="Merges transparent alpha channels onto a solid white background, eliminating hidden overlay tricks." />
                </label>

                <label className="flex items-center justify-between p-2.5 bg-white rounded-xl border border-slate-200 cursor-pointer hover:border-slate-300 transition-colors">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={options.convert_to_png}
                      onChange={() => handleToggle('convert_to_png')}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    <span className="font-medium text-slate-800">Convert to PNG</span>
                  </div>
                  <InfoPopover title="PNG Reformatting" content="Standardizes output image into a clean, uncompressed PNG container." />
                </label>
              </>
            )}
          </div>
        </div>
      )}

      {/* Category-Specific Output Format Selection */}
      <div className="mb-6 p-5 bg-slate-50 rounded-2xl border border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-700 font-bold flex items-center gap-2">
            <span>📦</span>
            <span>Select Output File Format</span>
          </h4>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-blue-100 text-blue-800 border border-blue-200 uppercase self-start sm:self-auto">
            Target Format: {currentOption.badge}
          </span>
        </div>

        {formatConfig.lockedNotice && (
          <div className="mb-3 p-3 bg-blue-50/80 border border-blue-200 rounded-xl text-xs text-blue-900 flex items-start gap-2">
            <span className="text-blue-600 mt-0.5">ℹ️</span>
            <span className="leading-relaxed">{formatConfig.lockedNotice}</span>
          </div>
        )}

        <div className={`grid grid-cols-1 ${formatConfig.options.length > 2 ? 'sm:grid-cols-3' : formatConfig.options.length === 2 ? 'sm:grid-cols-2' : 'sm:grid-cols-1'} gap-3 mb-3`}>
          {formatConfig.options.map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => handleFormatSelect(opt.id)}
              className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
                outputFormat === opt.id
                  ? 'bg-white border-blue-600 ring-2 ring-blue-500/20 shadow-xs'
                  : 'bg-white/80 border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="font-bold text-xs text-slate-900 mb-1 flex items-center justify-between gap-2">
                <span>{opt.title}</span>
                <span className={`text-[10px] ${opt.badgeBg} ${opt.badgeText} px-1.5 py-0.2 rounded font-mono font-bold shrink-0`}>
                  {opt.badge}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 leading-relaxed">
                {opt.desc}
              </p>
            </button>
          ))}
        </div>

        {/* Explain resulting file type */}
        <div className="text-xs text-slate-600 bg-white p-3 rounded-xl border border-slate-200">
          <span className="font-semibold text-slate-800">What will happen: </span>
          <span>{currentOption.whatHappens}</span>
        </div>
      </div>

      {/* Action Trigger */}
      <div className="pt-4 border-t border-slate-100 space-y-3">
        {isMalicious && (
          <div className="p-3.5 bg-amber-50 border border-amber-200 rounded-2xl text-xs text-amber-950 flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-600 mt-0.5 shrink-0" />
            <div className="space-y-0.5">
              <strong className="block text-amber-900 font-bold">Threat Indicators Present in File</strong>
              <span className="text-amber-800 leading-relaxed">
                Content Disarm & Reconstruction (CDR) will aggressively strip and eradicate active scripts, malicious macros, exploit streams, and dangerous objects to produce a harmless artifact.
              </span>
            </div>
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="text-xs text-slate-500">
            * Original file remains isolated and immutable in the zero-trust sandbox.
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
            {isCompleted && onDownload && (
              <button
                type="button"
                onClick={onDownload}
                className="w-full sm:w-auto px-6 py-3.5 font-bold text-sm rounded-xl shadow-sm bg-emerald-600 hover:bg-emerald-700 text-white flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                <Download className="w-4 h-4" />
                <span>Download Clean File</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => onSanitize(selectedProfile, options)}
              disabled={isProcessing}
              className={`w-full sm:w-auto px-8 py-3.5 font-semibold text-sm rounded-xl shadow-sm transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer ${
                isProcessing
                  ? 'bg-slate-300 text-slate-500 cursor-not-allowed'
                  : isMalicious
                  ? 'bg-rose-600 hover:bg-rose-700 text-white'
                  : 'bg-slate-900 hover:bg-blue-600 text-white'
              }`}
            >
              <Sparkles className="w-4 h-4" />
              <span>
                {isProcessing
                  ? 'Disarming & Processing...'
                  : isCompleted
                  ? 'Re-Disarm & Sanitize'
                  : isMalicious
                  ? 'Disarm & Neutralize Threats'
                  : 'Clean & Disarm File'}
              </span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
