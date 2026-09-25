import React, { useState } from 'react';
import { 
  FileCheck2, 
  Image as ImageIcon, 
  FileText, 
  FileCode, 
  Archive, 
  FileSpreadsheet, 
  ShieldCheck, 
  Wrench, 
  Search, 
  ArrowRight,
  ShieldAlert,
  Sparkles
} from 'lucide-react';

interface SupportedFormatsProps {
  onGoToSanitizer: () => void;
}

export const SupportedFormats: React.FC<SupportedFormatsProps> = ({ onGoToSanitizer }) => {
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const formatCategories = [
    {
      id: "images",
      category: "Images & Photographs",
      icon: ImageIcon,
      iconColor: "text-blue-600 bg-blue-50 border-blue-200",
      extensions: [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff", ".tif"],
      description: "Standard digital imagery and photographs frequently leak device fingerprints, exact physical location, and embedded tracking pixels.",
      threats: ["Physical Geolocation Stalking", "Hardware Device Fingerprinting", "Hidden Steganographic Payloads", "Embedded Tracking Beacons"],
      checks: [
        "EXIF metadata (Camera Make, Model, Body Serial Number, Lens Model, Software)",
        "GPS geographic coordinates (Latitude, Longitude, Altitude, Geodetic Datum)",
        "Author, photographer, artist, and copyright attribution tags",
        "Creation, camera shutter, and software digitization timestamps",
        "Embedded text comments, annotation chunks, and caption packets",
        "XMP (Extensible Metadata Platform) and IPTC core photo structures",
        "Embedded thumbnails, preview icons, and auxiliary image streams",
        "Embedded URLs within EXIF string headers or comment chunks",
        "ICC color profiles and alpha channel transparency masks"
      ],
      sanitizations: [
        "Strip all EXIF, XMP, IPTC, and comment metadata packets",
        "Remove GPS geographic location coordinates permanently",
        "Eradicate photographer, artist, and copyright tags",
        "Strip creation and digitization timestamps",
        "Re-encode raw pixel data (purges slack space & hidden payloads)",
        "Lossless format conversion (Convert to PNG or JPG)",
        "Flatten image: composite transparency channels onto a pure white background"
      ]
    },
    {
      id: "pdf",
      category: "PDF Documents",
      icon: FileText,
      iconColor: "text-rose-600 bg-rose-50 border-rose-200",
      extensions: [".pdf", ".pdfa"],
      description: "Portable Document Format documents are complex multi-stream containers that can harbor active scripting, file attachments, and remote trigger actions.",
      threats: ["Embedded Heap-Spray Exploits", "Automatic Command Execution (/Launch)", "Phishing via JavaScript Popups", "Credential-Stealing Dynamic Forms"],
      checks: [
        "Document catalog metadata (Author, Title, Subject, Creator, Producer, Dates)",
        "Active JavaScript actions (embedded /JS objects and document scripts)",
        "/Launch actions and automatic /OpenAction triggers",
        "Embedded file attachments and secondary document payloads (/EmbeddedFiles, /EF)",
        "Interactive AcroForms and dynamic XML Forms Architecture (XFA)",
        "External hyperlinks, URI stream actions, and remote document references",
        "Embedded rich media objects (screen annotations, movie clips, 3D streams)",
        "Multiple incremental updates (revision history masking shadow attacks)",
        "Password protection, encryption markers, and exploit structural tokens"
      ],
      sanitizations: [
        "Strip document author, title, producer, and modification timestamps",
        "Purge active JavaScript streams and automated /OpenAction hooks",
        "Eradicate /Launch actions capable of executing local programs",
        "Permanently remove embedded file attachments and secondary files",
        "Flatten interactive AcroForms and dynamic XFA form structures",
        "Neutralize and strip external hyperlinks and /URI actions",
        "Maximum Rasterization CDR: renders every page to an image and compiles a completely fresh PDF"
      ]
    },
    {
      id: "office",
      category: "Microsoft Office Documents",
      icon: FileSpreadsheet,
      iconColor: "text-amber-600 bg-amber-50 border-amber-200",
      extensions: [".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".rtf", ".odt", ".ods", ".odp"],
      description: "Word processing, spreadsheet, and presentation documents containing rich macros, dynamic relationships, and revision markup.",
      threats: ["VBA Macro Droppers / Ransomware", "Remote Template Injection Attacks", "ActiveX Remote Code Execution", "Tracked Change Information Leakage"],
      checks: [
        "Visual Basic for Applications (VBA) macro binary streams (vbaProject.bin)",
        "ActiveX controls and embedded OLE storage objects",
        "Remote template injection (attachedTemplate relationships in .rels)",
        "External relationships and remote web resource references",
        "Tracked changes (revisions, deletions, insertions, author timestamps)",
        "Internal author comments, reviewer remarks, and unresolved notes",
        "Core metadata (dc:creator, cp:lastModifiedBy, dc:title, dc:description, cp:keywords)",
        "Custom document properties in docProps/custom.xml",
        "Hyperlinks and URLs embedded in document text or relationship targets"
      ],
      sanitizations: [
        "Purge all VBA macro binary streams (vbaProject.bin) without executing them",
        "Strip embedded ActiveX controls and OLE storage objects",
        "Neutralize external relationships and remote attached template targets",
        "Scrub personal author and modifier metadata from docProps/core.xml",
        "Permanently delete tracked revisions and internal reviewer comments",
        "Downgrade macroEnabled container types (.docm/.xlsm) to standard safe formats (.docx/.xlsx)"
      ]
    },
    {
      id: "archives",
      category: "Compressed Archives",
      icon: Archive,
      iconColor: "text-purple-600 bg-purple-50 border-purple-200",
      extensions: [".zip", ".7z", ".tar", ".gz", ".tgz"],
      description: "Compressed packages that can bundle dangerous nested scripts, directory traversal paths, or excessive decompression payloads.",
      threats: ["Path Traversal Arbitrary File Overwrite", "Zip Bombs / Decompression Denial of Service", "Executable Droppers (.exe, .ps1, .bat)", "Hidden Nested Archives"],
      checks: [
        "Directory traversal filenames (../../etc/passwd, ..\\windows\\system32)",
        "Executable and script members (.exe, .dll, .bat, .cmd, .ps1, .vbs, .sh, .py)",
        "Excessive compression ratios / zip bombs (>100:1 ratio against uncompressed size)",
        "Recursive nested archives exceeding extraction limits",
        "Encrypted and password-protected member files",
        "Absolute file paths and symbolic link targets"
      ],
      sanitizations: [
        "Filter and exclude directory traversal filenames",
        "Purge executable binaries, installer scripts, and PowerShell droppers",
        "Enforce strict decompression limits on member sizes and recursion depth",
        "Reconstruct clean, standardized ZIP archive containing only safe data files"
      ]
    },
    {
      id: "web",
      category: "Vector Graphics & Active Web",
      icon: FileCode,
      iconColor: "text-emerald-600 bg-emerald-50 border-emerald-200",
      extensions: [".svg", ".html", ".htm"],
      description: "Markup documents executed directly by web browsers, making them vectors for cross-site scripting (XSS), credential phishing, and tracking.",
      threats: ["Browser DOM Cross-Site Scripting (XSS)", "Credential Harvesting Phishing Forms", "Zero-Pixel Tracking Beacons", "Malicious Meta Refresh Redirects"],
      checks: [
        "Executable <script> elements and client-side JavaScript payloads",
        "Inline DOM event handlers (onload, onerror, onclick, onmouseover, onsubmit)",
        "javascript: and data: pseudo-protocol URIs in anchors and xlink targets",
        "Credential phishing forms (<form action=...> and submit buttons)",
        "External tracking beacons, remote images, and analytics scripts",
        "Embedded iframes (<iframe src=...> mirroring external portals)",
        "Meta refresh redirects (<meta http-equiv=\"refresh\">) and external links"
      ],
      sanitizations: [
        "Strip all <script> tags and executable JavaScript code",
        "Remove inline DOM event handlers (onload, onerror, etc.)",
        "Neutralize and decompose credential forms and form fields",
        "Strip embedded iframes and third-party tracking beacons",
        "Rasterize SVG directly to clean, inert PNG or JPEG raster image (Safest CDR)"
      ]
    },
    {
      id: "data",
      category: "Plain Text & Spreadsheets",
      icon: FileCheck2,
      iconColor: "text-slate-600 bg-slate-100 border-slate-200",
      extensions: [".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md"],
      description: "Structured and tabular data susceptible to formula injection (DDE), encoding attacks, or embedded remote dropper links.",
      threats: ["CSV Formula Execution / DDE Injection", "Arbitrary Command Execution (=cmd|...)", "Encoding Confusables & BOM Tricks", "Phishing URLs in Data Columns"],
      checks: [
        "CSV Formula / Dynamic Data Exchange (DDE) prefixes (=cmd|..., +powershell..., @SUM...)",
        "Character encoding identification (UTF-8, UTF-16LE, UTF-16BE) and BOM presence",
        "Suspicious shell command strings, PowerShell execution arguments, and downloader URLs",
        "XML External Entity (XXE) expansion indicators and entity bombs",
        "Embedded URLs and external web links"
      ],
      sanitizations: [
        "Escape dangerous spreadsheet formula execution prefixes with safe leading single quote (')",
        "Normalize character encoding to standard UTF-8",
        "Strip dangerous Byte Order Mark (BOM) bytes"
      ]
    }
  ];

  const filteredCategories = formatCategories.filter(cat => {
    const matchesCategory = activeCategory === 'all' || cat.id === activeCategory;
    const matchesSearch = searchTerm.trim() === '' || 
      cat.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cat.extensions.some(ext => ext.toLowerCase().includes(searchTerm.toLowerCase())) ||
      cat.checks.some(c => c.toLowerCase().includes(searchTerm.toLowerCase())) ||
      cat.threats.some(t => t.toLowerCase().includes(searchTerm.toLowerCase()));

    return matchesCategory && matchesSearch;
  });

  return (
    <div className="max-w-6xl mx-auto py-10 px-4 sm:px-6 lg:px-8 space-y-10">
      {/* Header */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 bg-slate-100 rounded-full text-xs font-mono text-slate-700 border border-slate-200">
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span>Complete Format Inspection Matrix</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
          Supported Files & Security Checks
        </h1>
        <p className="text-base sm:text-lg text-slate-600 leading-relaxed">
          Explore the exact security indicators, active threats, and Content Disarm & Reconstruction 
          transformations applied to each file format.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
          {/* Category Tabs */}
          <div className="flex flex-wrap gap-1.5 w-full sm:w-auto">
            <button
              onClick={() => setActiveCategory('all')}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                activeCategory === 'all'
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              All Formats ({formatCategories.length})
            </button>
            {formatCategories.map(c => (
              <button
                key={c.id}
                onClick={() => setActiveCategory(c.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                  activeCategory === c.id
                    ? 'bg-slate-900 text-white shadow-sm'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {c.category.split(' ')[0]}
              </button>
            ))}
          </div>

          {/* Search Input */}
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search checks, threats, ext..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white"
            />
          </div>
        </div>
      </div>

      {/* Format Cards */}
      <div className="space-y-6">
        {filteredCategories.length === 0 ? (
          <div className="text-center py-12 bg-white border border-slate-200 rounded-3xl p-8">
            <p className="text-sm text-slate-500">No formats match your search query "{searchTerm}".</p>
            <button
              onClick={() => { setActiveCategory('all'); setSearchTerm(''); }}
              className="mt-3 text-xs text-blue-600 font-semibold hover:underline"
            >
              Reset filters
            </button>
          </div>
        ) : (
          filteredCategories.map((c) => {
            const Icon = c.icon;
            return (
              <div 
                key={c.id}
                className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm space-y-6 hover:border-slate-300 transition-all"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-5">
                  <div className="flex items-center gap-3">
                    <div className={`w-12 h-12 rounded-2xl flex items-center justify-center border shadow-xs ${c.iconColor}`}>
                      <Icon className="w-6 h-6" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-slate-900">{c.category}</h3>
                      <p className="text-xs text-slate-500">{c.description}</p>
                    </div>
                  </div>

                  {/* Extension Badges */}
                  <div className="flex flex-wrap gap-1.5 items-center">
                    {c.extensions.map((ext) => (
                      <span 
                        key={ext}
                        className="px-2 py-0.5 bg-slate-100 text-slate-700 text-xs font-mono font-medium rounded-lg border border-slate-200"
                      >
                        {ext}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Mitigated Threats */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                    <span>Key Threat Vectors Disarmed</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {c.threats.map((threat, idx) => (
                      <span 
                        key={idx}
                        className="px-2.5 py-1 bg-amber-50/70 border border-amber-200/80 text-amber-800 text-xs font-medium rounded-full"
                      >
                        {threat}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Two Column Grid: Security Checks vs Sanitization Options */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-2">
                  {/* Checks Column */}
                  <div className="bg-slate-50 border border-slate-100 rounded-2xl p-5 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      <span>Security & Integrity Analysis ({c.checks.length})</span>
                    </div>
                    <ul className="space-y-2">
                      {c.checks.map((chk, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-xs text-slate-600 font-normal leading-relaxed">
                          <span className="text-emerald-500 font-bold mt-0.5">•</span>
                          <span>{chk}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Sanitization Column */}
                  <div className="bg-blue-50/40 border border-blue-100 rounded-2xl p-5 space-y-3">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                      <Wrench className="w-4 h-4 text-blue-600" />
                      <span>Content Disarm & Reconstruction ({c.sanitizations.length})</span>
                    </div>
                    <ul className="space-y-2">
                      {c.sanitizations.map((san, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-xs text-slate-700 font-normal leading-relaxed">
                          <span className="text-blue-500 font-bold mt-0.5">•</span>
                          <span>{san}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* CTA Footer */}
      <div className="text-center pt-4">
        <button
          onClick={onGoToSanitizer}
          className="px-6 py-3 bg-slate-900 hover:bg-blue-600 text-white font-medium text-sm rounded-xl shadow-sm transition-all inline-flex items-center gap-2 cursor-pointer"
        >
          <span>Return to File Sanitizer</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
