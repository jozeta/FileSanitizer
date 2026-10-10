import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  Binary,
  Code,
  Search,
  Copy,
  Sparkles,
  Layers,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ArrowRight,
  Loader2,
  X
} from 'lucide-react';
import { apiClient } from '../api/client';

import {
  PatternDefinition,
  StructureType,
  FileFormatDefinition,
  DEFAULT_FILE_FORMATS,
  STRUCTURE_COLORS,
  BUILTIN_FORMAT_PATTERNS
} from '../utils/fileFormatPatterns';

export type { PatternDefinition, StructureType, FileFormatDefinition };
export { STRUCTURE_COLORS, BUILTIN_FORMAT_PATTERNS, DEFAULT_FILE_FORMATS };

interface HexRawInspectorProps {
  jobId: string;
  filename: string;
  category?: string;
  initialViewMode?: 'hex' | 'text' | 'bytes';
}

interface HighlightSpan {
  start: number;
  end: number;
  pattern: PatternDefinition;
}

const CHUNK_SIZE = 65536; // 64 KB per background chunk
const PAGE_SIZE = 1024;   // 1024 bytes (64 lines of 16 bytes) per view page

export const HexRawInspector: React.FC<HexRawInspectorProps> = ({
  jobId,
  filename,
  category = 'binary',
  initialViewMode = 'hex'
}) => {
  const [viewMode, setViewMode] = useState<'hex' | 'text' | 'bytes'>(initialViewMode);
  const [loading, setLoading] = useState<boolean>(true);
  const [backgroundFetching, setBackgroundFetching] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [fileSize, setFileSize] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(0);
  const [jumpInput, setJumpInput] = useState<string>('');

  // In-memory chunk cache to avoid re-fetching and eliminate lag
  // Key: chunkIndex (offset / CHUNK_SIZE), Value: Uint8Array
  const chunkCache = useRef<Map<number, Uint8Array>>(new Map());
  const textCache = useRef<Map<number, string>>(new Map());

  // Search state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchMode, setSearchMode] = useState<'string' | 'hex'>('string');
  const [searchMatches, setSearchMatches] = useState<{ start: number; length: number }[]>([]);

  // Formats state (built-in + custom from settings)
  const [fileFormats, setFileFormats] = useState<FileFormatDefinition[]>(DEFAULT_FILE_FORMATS);
  const [selectedFormat, setSelectedFormat] = useState<string>('pe');
  const userOverrodeFormat = useRef<boolean>(false);

  // Patterns state (built-in + custom from settings/localStorage)
  const [patterns, setPatterns] = useState<PatternDefinition[]>([]);
  const [hoveredPattern, setHoveredPattern] = useState<{
    pattern: PatternDefinition;
    start: number;
    end: number;
    hexSnippet: string;
    x: number;
    y: number;
  } | null>(null);

  // Bidirectional Selection & Hover Synchronization
  const [hoveredByteGlobal, setHoveredByteGlobal] = useState<number | null>(null);
  const [selectionRange, setSelectionRange] = useState<{ start: number; end: number } | null>(null);
  const [isSelecting, setIsSelecting] = useState<boolean>(false);
  const [selectionAnchor, setSelectionAnchor] = useState<number | null>(null);

  const [showActivePatternsPopover, setShowActivePatternsPopover] = useState<boolean>(false);

  // Load custom patterns & formats
  useEffect(() => {
    const loadData = async () => {
      let custom: PatternDefinition[] = [];
      try {
        const res = await apiClient.getCustomPatterns().catch(() => ({ patterns: [] }));
        if (res.patterns && res.patterns.length > 0) {
          custom = res.patterns;
        }
      } catch {
        const stored = localStorage.getItem('filesanitizer_custom_hex_patterns');
        if (stored) {
          try {
            custom = JSON.parse(stored);
          } catch {}
        }
      }
      
      const patternMap = new Map<string, PatternDefinition>();
      for (const p of BUILTIN_FORMAT_PATTERNS) {
        patternMap.set(p.id, { ...p, isBuiltin: true });
      }
      for (const p of custom) {
        patternMap.set(p.id, p);
      }
      setPatterns(Array.from(patternMap.values()));

      try {
        const fmtRes = await apiClient.getFileFormats().catch(() => ({ formats: [] }));
        if (fmtRes.formats && fmtRes.formats.length > 0) {
          setFileFormats(fmtRes.formats);
        }
      } catch {}
    };
    loadData();
  }, []);

  // Fetch chunk helper
  const fetchChunk = useCallback(async (chunkIdx: number): Promise<Uint8Array | null> => {
    if (chunkCache.current.has(chunkIdx)) {
      return chunkCache.current.get(chunkIdx)!;
    }

    try {
      setBackgroundFetching(true);
      const chunkOffset = chunkIdx * CHUNK_SIZE;
      const data = await apiClient.getRawContent(jobId, chunkOffset, CHUNK_SIZE);
      if (data.file_size !== undefined) {
        setFileSize(data.file_size);
      }
      if (data.text) {
        textCache.current.set(chunkIdx, data.text);
      }

      let bytes = new Uint8Array(0);
      if (data.b64) {
        const binStr = atob(data.b64);
        bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
          bytes[i] = binStr.charCodeAt(i);
        }
      }
      chunkCache.current.set(chunkIdx, bytes);
      return bytes;
    } catch (err: any) {
      console.error(`Error loading chunk ${chunkIdx}:`, err);
      return null;
    } finally {
      setBackgroundFetching(false);
    }
  }, [jobId]);

  // Initial load: fetch chunk 0
  useEffect(() => {
    let isMounted = true;
    const init = async () => {
      setLoading(true);
      setError(null);
      try {
        const b = await fetchChunk(0);
        if (!isMounted) return;
        if (!b) setError('Failed to retrieve file contents.');
      } catch (err: any) {
        if (isMounted) setError(err.message || 'Failed to inspect file.');
      } finally {
        if (isMounted) setLoading(false);
      }
    };
    init();
    return () => { isMounted = false; };
  }, [fetchChunk]);

  // Total pages
  const totalPages = useMemo(() => {
    if (fileSize <= 0) return 1;
    return Math.max(1, Math.ceil(fileSize / PAGE_SIZE));
  }, [fileSize]);

  // Load target page data
  const currentChunkIdx = Math.floor((currentPage * PAGE_SIZE) / CHUNK_SIZE);

  useEffect(() => {
    if (!chunkCache.current.has(currentChunkIdx)) {
      fetchChunk(currentChunkIdx);
    }
    // Proactively prefetch next chunk if close
    const nextChunk = currentChunkIdx + 1;
    if (nextChunk * CHUNK_SIZE < fileSize && !chunkCache.current.has(nextChunk)) {
      fetchChunk(nextChunk);
    }
  }, [currentPage, currentChunkIdx, fetchChunk, fileSize]);

  // Current page bytes slice
  const pageBytes = useMemo(() => {
    const pageGlobalOffset = currentPage * PAGE_SIZE;
    const chunkStartOffset = currentChunkIdx * CHUNK_SIZE;
    const offsetWithinChunk = pageGlobalOffset - chunkStartOffset;

    const chunk = chunkCache.current.get(currentChunkIdx);
    if (!chunk || chunk.length === 0) {
      return new Uint8Array(0);
    }

    const available = chunk.length - offsetWithinChunk;
    if (available >= PAGE_SIZE) {
      return chunk.slice(offsetWithinChunk, offsetWithinChunk + PAGE_SIZE);
    }

    // Spans across chunk boundary
    const part1 = chunk.slice(offsetWithinChunk);
    const nextChunk = chunkCache.current.get(currentChunkIdx + 1);
    if (nextChunk && nextChunk.length > 0) {
      const needed = Math.min(PAGE_SIZE - part1.length, nextChunk.length);
      const part2 = nextChunk.slice(0, needed);
      const combined = new Uint8Array(part1.length + part2.length);
      combined.set(part1, 0);
      combined.set(part2, part1.length);
      return combined;
    }
    return part1;
  }, [currentPage, currentChunkIdx, backgroundFetching]);

  // Text representation for current page
  const pageText = useMemo(() => {
    if (pageBytes.length === 0) return '';
    let res = '';
    for (let i = 0; i < pageBytes.length; i++) {
      const b = pageBytes[i];
      res += (b === 10 || b === 13 || (b >= 32 && b <= 126)) ? String.fromCharCode(b) : '.';
    }
    return res;
  }, [pageBytes]);

  // Format detection from chunk 0 bytes and filename
  const detectedFormat = useMemo(() => {
    const b0 = chunkCache.current.get(0);
    if (b0 && b0.length >= 4) {
      if (b0[0] === 0x4d && b0[1] === 0x5a) return 'pe';
      if (b0[0] === 0x7f && b0[1] === 0x45 && b0[2] === 0x4c && b0[3] === 0x46) return 'elf';
      if (b0[0] === 0xcf && b0[1] === 0xfa && b0[2] === 0xed && b0[3] === 0xfe) return 'macho';
      if (b0[0] === 0xfe && b0[1] === 0xed && b0[2] === 0xfa && b0[3] === 0xcf) return 'macho';
      if (b0[0] === 0x89 && b0[1] === 0x50 && b0[2] === 0x4e && b0[3] === 0x47) return 'png';
      if (b0[0] === 0xff && b0[1] === 0xd8 && b0[2] === 0xff) return 'jpeg';
      if (b0[0] === 0x47 && b0[1] === 0x49 && b0[2] === 0x46) return 'gif';
      if (
        b0[0] === 0x52 &&
        b0[1] === 0x49 &&
        b0[2] === 0x46 &&
        b0[3] === 0x46 &&
        b0.length >= 12 &&
        b0[8] === 0x57 &&
        b0[9] === 0x45 &&
        b0[10] === 0x42 &&
        b0[11] === 0x50
      )
        return 'webp';
      if (b0[0] === 0x50 && b0[1] === 0x4b && b0[2] === 0x03 && b0[3] === 0x04) return 'zip';
      if (b0[0] === 0x52 && b0[1] === 0x61 && b0[2] === 0x72 && b0[3] === 0x21) return 'rar';
      if (b0[0] === 0xd0 && b0[1] === 0xcf && b0[2] === 0x11 && b0[3] === 0xe0) return 'cfb';
      if (b0[0] === 0x25 && b0[1] === 0x50 && b0[2] === 0x44 && b0[3] === 0x46) return 'pdf';
      if (b0[0] === 0x37 && b0[1] === 0x7a && b0[2] === 0xbc && b0[3] === 0xaf) return '7z';
      if (b0[0] === 0x43 && b0[1] === 0x72 && b0[2] === 0x32 && b0[3] === 0x34) return 'crx';
      if (b0[0] === 0xca && b0[1] === 0xfe && b0[2] === 0xba && b0[3] === 0xbe) return 'class';
      if (b0[0] === 0x75 && b0[1] === 0x73 && b0[2] === 0x74 && b0[3] === 0x61) return 'tar';
    }

    // Fallback to filename extension or category
    const lowerName = (filename || '').toLowerCase();
    if (lowerName.endsWith('.exe') || lowerName.endsWith('.dll') || lowerName.endsWith('.sys')) return 'pe';
    if (lowerName.endsWith('.elf') || lowerName.endsWith('.so') || category === 'binary' || category === 'executable') return 'elf';
    if (lowerName.endsWith('.pdf')) return 'pdf';
    if (lowerName.endsWith('.rar')) return 'rar';
    if (lowerName.endsWith('.zip') || lowerName.endsWith('.jar')) return 'zip';
    if (lowerName.endsWith('.7z')) return '7z';
    if (lowerName.match(/\.(docx?|xlsx?|pptx?|docm|xlsm|pptm|dot|msg|eml)$/i)) return 'cfb';
    if (lowerName.endsWith('.class')) return 'class';
    if (lowerName.endsWith('.crx')) return 'crx';
    if (lowerName.endsWith('.png')) return 'png';
    if (lowerName.match(/\.(jpe?g)$/i)) return 'jpeg';
    if (lowerName.endsWith('.gif')) return 'gif';
    if (lowerName.endsWith('.webp')) return 'webp';
    if (lowerName.endsWith('.tar')) return 'tar';
    return 'pe';
  }, [pageBytes, filename, category]);

  // Synchronize selectedFormat with detectedFormat unless user explicitly changed it
  useEffect(() => {
    if (!userOverrodeFormat.current && detectedFormat) {
      setSelectedFormat(detectedFormat);
    }
  }, [detectedFormat]);

  // Active pattern definitions for the selected format
  const selectedFormatPatterns = useMemo(() => {
    return patterns.filter((p) => p.enabled !== false && p.appliesToFormat === selectedFormat);
  }, [patterns, selectedFormat]);

  // Pattern detection for current page slice - strictly applied to selected format
  const patternSpans = useMemo<HighlightSpan[]>(() => {
    if (pageBytes.length === 0) return [];
    const spans: HighlightSpan[] = [];
    const activePatterns = selectedFormatPatterns;
    const pageGlobalStart = currentPage * PAGE_SIZE;
    const pageGlobalEnd = pageGlobalStart + pageBytes.length;

    for (const pat of activePatterns) {
      if (pat.type === 'struct_field' || (pat.offset !== undefined && pat.length !== undefined)) {
        const offset = pat.offset ?? 0;
        const length = pat.length ?? 1;
        const fieldEnd = offset + length;
        if (offset < pageGlobalEnd && fieldEnd > pageGlobalStart) {
          const relStart = Math.max(0, offset - pageGlobalStart);
          const relEnd = Math.min(pageBytes.length, fieldEnd - pageGlobalStart);
          if (relStart < relEnd) {
            spans.push({ start: relStart, end: relEnd, pattern: pat });
          }
        }
        continue;
      }

      if (pat.type === 'hex') {
        const cleanHex = pat.pattern.replace(/\s+/g, '').toUpperCase();
        if (cleanHex.length % 2 !== 0) continue;
        const targetBytes: number[] = [];
        for (let i = 0; i < cleanHex.length; i += 2) {
          targetBytes.push(parseInt(cleanHex.substring(i, i + 2), 16));
        }
        if (targetBytes.length === 0) continue;

        // Exact offset pattern (e.g. 0x00 for magic headers, 0x3C for e_lfanew)
        if (pat.offset !== undefined) {
          if (pat.offset >= pageGlobalStart && pat.offset + targetBytes.length <= pageGlobalEnd) {
            const relOffset = pat.offset - pageGlobalStart;
            let match = true;
            for (let j = 0; j < targetBytes.length; j++) {
              if (pageBytes[relOffset + j] !== targetBytes[j]) {
                match = false;
                break;
              }
            }
            if (match) {
              spans.push({ start: relOffset, end: relOffset + targetBytes.length, pattern: pat });
            }
          }
          continue;
        }

        // Floating search within current page
        for (let i = 0; i <= pageBytes.length - targetBytes.length; i++) {
          let match = true;
          for (let j = 0; j < targetBytes.length; j++) {
            if (pageBytes[i + j] !== targetBytes[j]) {
              match = false;
              break;
            }
          }
          if (match) {
            spans.push({ start: i, end: i + targetBytes.length, pattern: pat });
          }
        }
      } else if (pat.type === 'string') {
        // Exact offset string pattern
        if (pat.offset !== undefined) {
          const needleBytes = new TextEncoder().encode(pat.pattern);
          if (pat.offset >= pageGlobalStart && pat.offset + needleBytes.length <= pageGlobalEnd) {
            const relOffset = pat.offset - pageGlobalStart;
            let match = true;
            for (let j = 0; j < needleBytes.length; j++) {
              if (pageBytes[relOffset + j] !== needleBytes[j]) {
                match = false;
                break;
              }
            }
            if (match) {
              spans.push({ start: relOffset, end: relOffset + needleBytes.length, pattern: pat });
            }
          }
          continue;
        }

        const needle = pat.pattern.toLowerCase();
        if (!needle) continue;
        const lowerText = pageText.toLowerCase();
        let idx = lowerText.indexOf(needle);
        while (idx !== -1) {
          spans.push({ start: idx, end: idx + needle.length, pattern: pat });
          idx = lowerText.indexOf(needle, idx + 1);
        }
      }
    }
    return spans;
  }, [pageBytes, pageText, selectedFormatPatterns, currentPage, selectedFormat]);

  // Search execution for current page
  useEffect(() => {
    if (!searchQuery.trim() || pageBytes.length === 0) {
      setSearchMatches([]);
      return;
    }
    const matches: { start: number; length: number }[] = [];

    if (searchMode === 'hex') {
      const cleanHex = searchQuery.replace(/\s+/g, '').toUpperCase();
      if (cleanHex.length % 2 === 0 && cleanHex.length > 0) {
        const targetBytes: number[] = [];
        for (let i = 0; i < cleanHex.length; i += 2) {
          targetBytes.push(parseInt(cleanHex.substring(i, i + 2), 16));
        }
        for (let i = 0; i <= pageBytes.length - targetBytes.length; i++) {
          let match = true;
          for (let j = 0; j < targetBytes.length; j++) {
            if (pageBytes[i + j] !== targetBytes[j]) {
              match = false;
              break;
            }
          }
          if (match) {
            matches.push({ start: i, length: targetBytes.length });
          }
        }
      }
    } else {
      const q = searchQuery.toLowerCase();
      const txt = pageText.toLowerCase();
      let pos = txt.indexOf(q);
      while (pos !== -1) {
        matches.push({ start: pos, length: q.length });
        pos = txt.indexOf(q, pos + 1);
      }
    }
    setSearchMatches(matches);
  }, [searchQuery, searchMode, pageBytes, pageText]);

  // Rows generator for 16-byte Forensic Hex Dump View (Digital Detective forensic style)
  const hexRows = useMemo(() => {
    const rows = [];
    const baseOffset = currentPage * PAGE_SIZE;
    const len = pageBytes.length;

    for (let i = 0; i < len; i += 16) {
      const chunk = pageBytes.slice(i, Math.min(i + 16, len));
      const rowOffset = baseOffset + i;
      rows.push({
        offsetNum: rowOffset,
        offsetHex: rowOffset.toString(16).padStart(8, '0').toUpperCase(),
        bytes: chunk,
        startIndex: i,
      });
    }
    return rows;
  }, [pageBytes, currentPage]);

  const handleJumpToOffset = (e: React.FormEvent) => {
    e.preventDefault();
    if (!jumpInput.trim()) return;
    let target = 0;
    const trimmed = jumpInput.trim();
    if (trimmed.toLowerCase().startsWith('0x')) {
      target = parseInt(trimmed.substring(2), 16);
    } else if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length >= 4 && !/^\d+$/.test(trimmed)) {
      target = parseInt(trimmed, 16);
    } else {
      target = parseInt(trimmed, 10);
    }

    if (!isNaN(target) && target >= 0) {
      const targetPage = Math.min(totalPages - 1, Math.floor(target / PAGE_SIZE));
      setCurrentPage(targetPage);
    }
  };



  const getPatternForByte = (idx: number): HighlightSpan | undefined => {
    return patternSpans.find((s) => idx >= s.start && idx < s.end);
  };

  const isSearchMatchByte = (idx: number): boolean => {
    return searchMatches.some((m) => idx >= m.start && idx < m.start + m.length);
  };

  // Bidirectional Selection Handlers
  const handleByteMouseDown = (globalOffset: number, e: React.MouseEvent) => {
    if (e.button !== 0) return; // Left mouse button only
    e.preventDefault();
    setIsSelecting(true);
    setSelectionAnchor(globalOffset);
    setSelectionRange({ start: globalOffset, end: globalOffset + 1 });
  };

  const handleByteMouseEnter = (globalOffset: number) => {
    setHoveredByteGlobal(globalOffset);
    if (isSelecting && selectionAnchor !== null) {
      const s = Math.min(selectionAnchor, globalOffset);
      const e = Math.max(selectionAnchor, globalOffset) + 1;
      setSelectionRange({ start: s, end: e });
    }
  };

  const handleByteMouseLeave = () => {
    setHoveredByteGlobal(null);
  };

  // Window-level mouseup and keydown listeners to finalize selection smoothly
  useEffect(() => {
    const handleGlobalMouseUp = () => {
      setIsSelecting(false);
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectionRange(null);
      }
    };

    window.addEventListener('mouseup', handleGlobalMouseUp);
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('mouseup', handleGlobalMouseUp);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  // Sync native browser text selection (e.g. when highlighting text with cursor)
  const handleContainerMouseUp = () => {
    const sel = window.getSelection();
    if (sel && !sel.isCollapsed) {
      const anchorNode = sel.anchorNode instanceof HTMLElement ? sel.anchorNode : sel.anchorNode?.parentElement;
      const focusNode = sel.focusNode instanceof HTMLElement ? sel.focusNode : sel.focusNode?.parentElement;
      const aOffsetStr = anchorNode?.closest('[data-global-offset]')?.getAttribute('data-global-offset');
      const fOffsetStr = focusNode?.closest('[data-global-offset]')?.getAttribute('data-global-offset');
      if (aOffsetStr !== null && aOffsetStr !== undefined && fOffsetStr !== null && fOffsetStr !== undefined) {
        const a = parseInt(aOffsetStr, 10);
        const f = parseInt(fOffsetStr, 10);
        if (!isNaN(a) && !isNaN(f)) {
          setSelectionRange({
            start: Math.min(a, f),
            end: Math.max(a, f) + 1,
          });
        }
      }
    }
  };

  // Selection Data Inspector conversions (010 Editor style)
  const selectedValues = useMemo(() => {
    if (!selectionRange) return null;
    const pageGlobalStart = currentPage * PAGE_SIZE;
    const pageGlobalEnd = pageGlobalStart + pageBytes.length;

    // Check intersection with current pageBytes
    const s = Math.max(pageGlobalStart, selectionRange.start);
    const e = Math.min(pageGlobalEnd, selectionRange.end);
    if (s >= e) return null;

    const relStart = s - pageGlobalStart;
    const relEnd = e - pageGlobalStart;
    const slice = pageBytes.slice(relStart, relEnd);
    if (slice.length === 0) return null;

    const hexStr = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    const asciiStr = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    const cArrayStr = Array.from(slice)
      .map((b) => '0x' + b.toString(16).padStart(2, '0').toUpperCase())
      .join(', ');

    const view = new DataView(slice.buffer, slice.byteOffset, slice.byteLength);

    const u8 = slice[0];
    const i8 = new Int8Array(slice.buffer, slice.byteOffset, 1)[0];
    const binary = u8.toString(2).padStart(8, '0');

    let u16le: number | undefined;
    let u16be: number | undefined;
    let i16le: number | undefined;
    if (slice.length >= 2) {
      u16le = view.getUint16(0, true);
      u16be = view.getUint16(0, false);
      i16le = view.getInt16(0, true);
    }

    let u32le: number | undefined;
    let u32be: number | undefined;
    let i32le: number | undefined;
    let f32le: string | undefined;
    if (slice.length >= 4) {
      u32le = view.getUint32(0, true);
      u32be = view.getUint32(0, false);
      i32le = view.getInt32(0, true);
      try {
        f32le = view.getFloat32(0, true).toPrecision(6);
      } catch {}
    }

    let u64le: string | undefined;
    if (slice.length >= 8) {
      try {
        u64le = view.getBigUint64(0, true).toString();
      } catch {}
    }

    // Active matching pattern at selection start
    const matchingPattern = patternSpans.find(
      (sp) => relStart >= sp.start && relStart < sp.end
    )?.pattern;

    return {
      slice,
      hexStr,
      asciiStr,
      cArrayStr,
      u8,
      i8,
      binary,
      u16le,
      u16be,
      i16le,
      u32le,
      u32be,
      i32le,
      f32le,
      u64le,
      matchingPattern,
    };
  }, [selectionRange, currentPage, pageBytes, patternSpans]);

  const handleCopySelectionHex = () => {
    if (!selectedValues) return;
    navigator.clipboard.writeText(selectedValues.hexStr);
  };

  const handleCopySelectionText = () => {
    if (!selectedValues) return;
    navigator.clipboard.writeText(selectedValues.asciiStr);
  };

  const handleCopySelectionCArray = () => {
    if (!selectedValues) return;
    navigator.clipboard.writeText(selectedValues.cArrayStr);
  };


  return (
    <div className="bg-white rounded-3xl border border-slate-200 p-6 shadow-sm space-y-4">
      {/* Top Header & View Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-3 border-b border-slate-100">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-2xl shrink-0">
            <Binary className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-bold text-slate-900">
                Universal Raw File &amp; Hex Inspector
              </h3>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-semibold border border-slate-200">
                {filename}
              </span>
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 font-bold border border-indigo-200">
                {category}
              </span>
              <span className="text-[11px] font-mono text-slate-500">
                ({(fileSize / 1024).toFixed(1)} KB)
              </span>
              {backgroundFetching && (
                <span className="inline-flex items-center gap-1 text-[10px] font-mono text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-full animate-pulse border border-indigo-200">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span>Loading chunk in background...</span>
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500">
              High-performance chunked inspection, Digital Detective compact forensic layout, and ImHex structure patterns.
            </p>
          </div>
        </div>

        {/* View Mode Toggle & Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-xl bg-slate-100 p-1 border border-slate-200 text-xs">
            <button
              onClick={() => setViewMode('hex')}
              className={`px-3 py-1 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                viewMode === 'hex'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Binary className="w-3.5 h-3.5" />
              <span>Hex View</span>
            </button>

            <button
              onClick={() => setViewMode('bytes')}
              className={`px-3 py-1 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                viewMode === 'bytes'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Byte View</span>
            </button>

            <button
              onClick={() => setViewMode('text')}
              className={`px-3 py-1 rounded-lg font-semibold flex items-center gap-1.5 transition-all ${
                viewMode === 'text'
                  ? 'bg-white text-indigo-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              <span>Text / Code</span>
            </button>
          </div>

          {/* File Format Selector Dropdown */}
          <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-xl shadow-2xs">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Format:</span>
            <select
              value={selectedFormat}
              onChange={(e) => {
                userOverrodeFormat.current = true;
                setSelectedFormat(e.target.value);
              }}
              className="bg-white border border-slate-300 rounded-lg px-2.5 py-1 text-xs font-semibold text-slate-800 focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer shadow-2xs"
            >
              {fileFormats.map((fmt) => (
                <option key={fmt.id} value={fmt.id}>
                  {fmt.name}
                </option>
              ))}
            </select>
            {detectedFormat !== selectedFormat && (
              <button
                type="button"
                onClick={() => {
                  userOverrodeFormat.current = false;
                  setSelectedFormat(detectedFormat);
                }}
                className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 underline cursor-pointer"
                title="Reset to analyzed format"
              >
                Reset ({detectedFormat.toUpperCase()})
              </button>
            )}
          </div>

          {/* Active Patterns Count Button with Hover Popover */}
          <div
            className="relative"
            onMouseEnter={() => setShowActivePatternsPopover(true)}
            onMouseLeave={() => setShowActivePatternsPopover(false)}
          >
            <button
              type="button"
              onClick={() => setShowActivePatternsPopover((prev) => !prev)}
              className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-50 border border-indigo-200 text-indigo-700 flex items-center gap-1.5 cursor-pointer hover:bg-indigo-100 transition-colors shadow-2xs"
              title="Patterns matching selected format applied to this view (hover for details)"
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
              <span>{selectedFormatPatterns.length} Patterns Active</span>
            </button>

            {showActivePatternsPopover && (
              <div className="absolute right-0 top-full mt-1.5 w-84 max-h-96 overflow-y-auto bg-slate-900 text-white rounded-2xl shadow-2xl border border-slate-700 p-3 z-50 animate-in fade-in zoom-in-95">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-2">
                  <span className="text-xs font-bold text-slate-200 truncate max-w-[200px]">
                    {fileFormats.find((f) => f.id === selectedFormat)?.name || selectedFormat.toUpperCase()}
                  </span>
                  <span className="text-[10px] text-indigo-300 font-mono shrink-0">
                    {selectedFormatPatterns.length} active
                  </span>
                </div>
                {selectedFormatPatterns.length === 0 ? (
                  <div className="text-xs text-slate-400 py-3 text-center">
                    No active patterns configured for this format.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {selectedFormatPatterns.map((pat) => (
                      <div
                        key={pat.id}
                        className="p-2 rounded-xl bg-slate-800/80 border border-slate-700/60"
                      >
                        <div className="flex items-center justify-between gap-1.5 mb-1">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <span
                              className="w-2.5 h-2.5 rounded-full shrink-0"
                              style={{ backgroundColor: pat.color || '#6366f1' }}
                            />
                            <span className="text-xs font-bold text-slate-100 truncate">
                              {pat.name}
                            </span>
                          </div>
                          <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 shrink-0">
                            {pat.structure_type || pat.type}
                          </span>
                        </div>
                        {pat.description && (
                          <p className="text-[11px] text-slate-300 leading-tight">
                            {pat.description}
                          </p>
                        )}
                        <div className="mt-1 flex items-center gap-2 text-[10px] font-mono text-slate-400">
                          {pat.offset !== undefined && (
                            <span>Offset: 0x{pat.offset.toString(16).toUpperCase()}</span>
                          )}
                          {pat.length !== undefined && (
                            <span>Len: {pat.length}B</span>
                          )}
                          {pat.pattern && (
                            <span className="truncate max-w-[150px]">Match: {pat.pattern}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Search Bar & Jump to Offset Control */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-2.5 bg-slate-50/80 rounded-2xl border border-slate-200 text-xs">
        {/* Search */}
        <div className="flex items-center gap-2 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder={searchMode === 'hex' ? 'Search hex bytes (e.g., 4D 5A or 7F 45)...' : 'Search strings in page...'}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-white border border-slate-200 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
            />
          </div>
          <div className="inline-flex rounded-xl bg-slate-200/80 p-0.5 border border-slate-200 text-[11px]">
            <button
              onClick={() => setSearchMode('string')}
              className={`px-2 py-1 rounded-lg font-medium transition-all ${
                searchMode === 'string' ? 'bg-white text-indigo-700 shadow-2xs' : 'text-slate-600'
              }`}
            >
              String
            </button>
            <button
              onClick={() => setSearchMode('hex')}
              className={`px-2 py-1 rounded-lg font-medium transition-all ${
                searchMode === 'hex' ? 'bg-white text-indigo-700 shadow-2xs' : 'text-slate-600'
              }`}
            >
              Hex
            </button>
          </div>
          {searchMatches.length > 0 && (
            <span className="px-2 py-1 bg-amber-100 text-amber-800 rounded-lg font-semibold text-[11px]">
              {searchMatches.length} match{searchMatches.length > 1 ? 'es' : ''}
            </span>
          )}
        </div>

        {/* Jump to Offset & Pagination Navigation */}
        <div className="flex items-center gap-2">
          <form onSubmit={handleJumpToOffset} className="flex items-center gap-1.5">
            <span className="text-[11px] text-slate-500 font-mono">Offset:</span>
            <input
              type="text"
              placeholder="0x0000"
              value={jumpInput}
              onChange={(e) => setJumpInput(e.target.value)}
              className="w-20 bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs text-slate-900 font-mono focus:outline-none focus:ring-1 focus:ring-indigo-500 text-center"
            />
            <button
              type="submit"
              className="p-1.5 bg-slate-200 hover:bg-slate-300 rounded-lg text-slate-700 transition-colors"
              title="Jump to offset"
            >
              <ArrowRight className="w-3 h-3" />
            </button>
          </form>

          {/* Page Pagination Controls */}
          <div className="flex items-center gap-1 border-l border-slate-200 pl-2">
            <button
              onClick={() => setCurrentPage(0)}
              disabled={currentPage === 0}
              className="p-1 rounded-lg hover:bg-slate-200 disabled:opacity-30 disabled:hover:bg-transparent text-slate-700 cursor-pointer"
              title="First Page"
            >
              <ChevronsLeft className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setCurrentPage(Math.max(0, currentPage - 1))}
              disabled={currentPage === 0}
              className="p-1 rounded-lg hover:bg-slate-200 disabled:opacity-30 disabled:hover:bg-transparent text-slate-700 cursor-pointer"
              title="Previous Page"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span className="text-[11px] font-mono text-slate-600 px-1">
              Page <strong className="text-slate-900">{currentPage + 1}</strong> / {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(Math.min(totalPages - 1, currentPage + 1))}
              disabled={currentPage >= totalPages - 1}
              className="p-1 rounded-lg hover:bg-slate-200 disabled:opacity-30 disabled:hover:bg-transparent text-slate-700 cursor-pointer"
              title="Next Page"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setCurrentPage(totalPages - 1)}
              disabled={currentPage >= totalPages - 1}
              className="p-1 rounded-lg hover:bg-slate-200 disabled:opacity-30 disabled:hover:bg-transparent text-slate-700 cursor-pointer"
              title="Last Page"
            >
              <ChevronsRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>



      {/* 010 Editor Style Active Selection Data Inspector Bar */}
      {!loading && !error && selectionRange && selectedValues && (
        <div className="bg-slate-900 text-white rounded-2xl p-3 border border-slate-700 shadow-xl space-y-2.5 text-xs animate-in fade-in duration-150">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2 py-0.5 bg-blue-600 text-white text-[11px] font-bold rounded-lg font-mono">
                Selection: 0x{selectionRange.start.toString(16).toUpperCase()} - 0x{(selectionRange.end - 1).toString(16).toUpperCase()}
              </span>
              <span className="text-slate-400 font-mono text-[11px]">
                (Dec: {selectionRange.start} - {selectionRange.end - 1})
              </span>
              <span className="px-2 py-0.5 bg-slate-800 text-slate-300 text-[11px] font-bold rounded-lg">
                {selectionRange.end - selectionRange.start} Byte{selectionRange.end - selectionRange.start > 1 ? 's' : ''}
              </span>
              {selectedValues.matchingPattern && (
                <span
                  className="px-2 py-0.5 text-white text-[10px] font-bold rounded-lg uppercase tracking-wider flex items-center gap-1.5"
                  style={{ backgroundColor: selectedValues.matchingPattern.color }}
                >
                  <Sparkles className="w-3 h-3 text-white" />
                  <span>{selectedValues.matchingPattern.name} ({selectedValues.matchingPattern.structure_type})</span>
                </span>
              )}
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleCopySelectionHex}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                title="Copy space-delimited Hex bytes"
              >
                <Copy className="w-3 h-3 text-indigo-400" />
                <span>Copy Hex</span>
              </button>
              <button
                type="button"
                onClick={handleCopySelectionText}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                title="Copy Decoded Text"
              >
                <Copy className="w-3 h-3 text-emerald-400" />
                <span>Copy Text</span>
              </button>
              <button
                type="button"
                onClick={handleCopySelectionCArray}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-[11px] font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                title="Copy C-style byte array (0x4D, 0x5A, ...)"
              >
                <Code className="w-3 h-3 text-amber-400" />
                <span>Copy C Array</span>
              </button>
              <button
                type="button"
                onClick={() => setSelectionRange(null)}
                className="p-1 bg-slate-800 hover:bg-rose-900/60 hover:text-rose-300 text-slate-400 rounded-lg transition-colors cursor-pointer ml-1"
                title="Clear Selection (Esc)"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Numerical Conversions (010 Editor Inspector style) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-8 gap-2 font-mono text-[11px]">
            {selectedValues.u8 !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Uint8 / Int8</div>
                <div className="text-emerald-400 font-semibold">{selectedValues.u8} / {selectedValues.i8}</div>
              </div>
            )}
            {selectedValues.binary !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800 col-span-2 sm:col-span-2">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Binary (8 Bits)</div>
                <div className="text-cyan-400 font-semibold tracking-wider">{selectedValues.binary}</div>
              </div>
            )}
            {selectedValues.u16le !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Uint16 (LE)</div>
                <div className="text-indigo-400 font-semibold">{selectedValues.u16le}</div>
              </div>
            )}
            {selectedValues.u16be !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Uint16 (BE)</div>
                <div className="text-indigo-400 font-semibold">{selectedValues.u16be}</div>
              </div>
            )}
            {selectedValues.u32le !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Uint32 (LE)</div>
                <div className="text-purple-400 font-semibold">{selectedValues.u32le}</div>
              </div>
            )}
            {selectedValues.u32be !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Uint32 (BE)</div>
                <div className="text-purple-400 font-semibold">{selectedValues.u32be}</div>
              </div>
            )}
            {selectedValues.i32le !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Int32 (LE)</div>
                <div className="text-amber-400 font-semibold">{selectedValues.i32le}</div>
              </div>
            )}
            {selectedValues.f32le !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Float32</div>
                <div className="text-rose-400 font-semibold">{selectedValues.f32le}</div>
              </div>
            )}
            {selectedValues.u64le !== undefined && (
              <div className="bg-slate-950/80 p-1.5 rounded-lg border border-slate-800 col-span-2">
                <div className="text-[9px] uppercase tracking-wider text-slate-500">Uint64 (LE)</div>
                <div className="text-emerald-300 font-semibold truncate">{selectedValues.u64le}</div>
              </div>
            )}
          </div>

          {/* Hex & ASCII Representation Preview */}
          <div className="flex flex-col sm:flex-row items-stretch gap-2 text-[11px] font-mono">
            <div className="flex-1 bg-slate-950/80 px-2.5 py-1.5 rounded-lg border border-slate-800 overflow-x-auto whitespace-nowrap">
              <span className="text-slate-500 select-none mr-2">HEX:</span>
              <span className="text-indigo-300 font-bold">{selectedValues.hexStr}</span>
            </div>
            <div className="flex-1 bg-slate-950/80 px-2.5 py-1.5 rounded-lg border border-slate-800 overflow-x-auto whitespace-nowrap">
              <span className="text-slate-500 select-none mr-2">TEXT:</span>
              <span className="text-emerald-300 font-bold">{selectedValues.asciiStr}</span>
            </div>
          </div>
        </div>
      )}

      {/* Main Viewing Surface */}
      {loading ? (
        <div className="flex flex-col items-center justify-center p-12 text-slate-400 space-y-2">
          <Loader2 className="w-6 h-6 animate-spin text-indigo-600" />
          <span className="text-xs font-mono">Initializing chunk inspector...</span>
        </div>
      ) : error ? (
        <div className="p-6 bg-rose-50 border border-rose-200 rounded-2xl text-xs text-rose-800 text-center font-mono">
          {error}
        </div>
      ) : viewMode === 'text' ? (
        /* Text / Code View */
        <div className="border border-slate-200 rounded-2xl overflow-hidden bg-white max-h-[500px] overflow-y-auto">
          <div className="flex font-mono text-xs leading-relaxed divide-x divide-slate-100">
            <div className="bg-slate-50 text-slate-400 py-2 px-3 select-none text-right font-mono min-w-[50px] space-y-0.5 border-r border-slate-200">
              {pageText.split('\n').map((_, i) => (
                <div key={i} className="text-[11px] leading-4 text-slate-400">
                  {i + 1}
                </div>
              ))}
            </div>
            <div className="p-2.5 text-slate-800 overflow-x-auto flex-1 font-mono space-y-0.5">
              {pageText.split('\n').map((line, i) => (
                <div key={i} className="text-[11px] leading-4 whitespace-pre hover:bg-slate-50">
                  {line || ' '}
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : viewMode === 'bytes' ? (
        /* Compact Forensic Byte View (Digital Detective Reference Style) */
        <div
          onMouseUp={handleContainerMouseUp}
          className="border border-slate-200 rounded-2xl overflow-hidden bg-white max-h-[500px] overflow-y-auto font-mono text-[11px]"
        >
          {/* Header */}
          <div className="sticky top-0 bg-slate-100 border-b border-slate-200 px-3 py-1.5 flex text-[10px] font-bold text-slate-600 uppercase tracking-wider select-none z-10">
            <span className="w-24 shrink-0">Offset</span>
            <div className="flex-1 flex gap-2">
              <span className="flex-1 min-w-[200px]">Bytes 00-07</span>
              <span className="flex-1 min-w-[200px]">Bytes 08-0F</span>
            </div>
            <span className="w-36 text-right pr-2">ASCII</span>
          </div>

          <div className="divide-y divide-slate-100">
            {hexRows.map((r) => (
              <div
                key={r.offsetNum}
                className="flex items-center px-3 py-0.5 hover:bg-indigo-50/40 transition-colors font-mono text-[11px] leading-4 select-none"
              >
                {/* Offset */}
                <span className="w-24 shrink-0 text-slate-600 font-semibold select-none">
                  {r.offsetHex}:
                </span>

                {/* Bytes 0-7 */}
                <div className="flex-1 flex items-center space-x-1">
                  {Array.from({ length: 8 }).map((_, byteIdx) => {
                    if (byteIdx >= r.bytes.length) {
                      return <span key={byteIdx} className="inline-block w-6 text-center text-transparent">..</span>;
                    }
                    const pageIdx = r.startIndex + byteIdx;
                    const globalOffset = r.offsetNum + byteIdx;
                    const byteVal = r.bytes[byteIdx];
                    const hexStr = byteVal.toString(16).padStart(2, '0').toUpperCase();
                    const pat = getPatternForByte(pageIdx);
                    const isMatch = isSearchMatchByte(pageIdx);
                    const isSelected =
                      selectionRange !== null &&
                      globalOffset >= selectionRange.start &&
                      globalOffset < selectionRange.end;
                    const isHovered = hoveredByteGlobal === globalOffset;

                    return (
                      <span
                        key={byteIdx}
                        data-global-offset={globalOffset}
                        onMouseDown={(e) => handleByteMouseDown(globalOffset, e)}
                        onMouseEnter={(e) => {
                          handleByteMouseEnter(globalOffset);
                          if (pat) {
                            const rect = e.currentTarget.getBoundingClientRect();
                            setHoveredPattern({
                              pattern: pat.pattern,
                              start: currentPage * PAGE_SIZE + pat.start,
                              end: currentPage * PAGE_SIZE + pat.end,
                              hexSnippet: hexStr,
                              x: rect.left + rect.width / 2,
                              y: rect.top,
                            });
                          }
                        }}
                        onMouseLeave={() => {
                          handleByteMouseLeave();
                          setHoveredPattern(null);
                        }}
                        style={{
                          backgroundColor: isSelected
                            ? '#2563eb'
                            : isMatch
                            ? '#fef08a'
                            : isHovered
                            ? '#e0e7ff'
                            : pat
                            ? `${pat.pattern.color}33`
                            : undefined,
                          borderBottom: !isSelected && pat ? `2px solid ${pat.pattern.color}` : undefined,
                        }}
                        className={`inline-block w-6 text-center rounded px-0.5 cursor-pointer select-none transition-colors ${
                          isSelected
                            ? 'bg-blue-600 text-white font-bold ring-1 ring-blue-400 shadow-xs z-1'
                            : isHovered
                            ? 'ring-2 ring-indigo-500 text-indigo-950 font-bold z-1'
                            : byteVal === 0
                            ? 'text-slate-400 font-medium'
                            : 'text-slate-800 font-medium'
                        }`}
                        title={`Offset 0x${globalOffset.toString(16).toUpperCase()} (${globalOffset}): ${byteVal} (0x${hexStr})`}
                      >
                        {byteVal}
                      </span>
                    );
                  })}
                </div>

                {/* Bytes 8-15 */}
                <div className="flex-1 flex items-center space-x-1 pl-2 border-l border-slate-200">
                  {Array.from({ length: 8 }).map((_, byteIdx) => {
                    const actualIdx = byteIdx + 8;
                    if (actualIdx >= r.bytes.length) {
                      return <span key={actualIdx} className="inline-block w-6 text-center text-transparent">..</span>;
                    }
                    const pageIdx = r.startIndex + actualIdx;
                    const globalOffset = r.offsetNum + actualIdx;
                    const byteVal = r.bytes[actualIdx];
                    const hexStr = byteVal.toString(16).padStart(2, '0').toUpperCase();
                    const pat = getPatternForByte(pageIdx);
                    const isMatch = isSearchMatchByte(pageIdx);
                    const isSelected =
                      selectionRange !== null &&
                      globalOffset >= selectionRange.start &&
                      globalOffset < selectionRange.end;
                    const isHovered = hoveredByteGlobal === globalOffset;

                    return (
                      <span
                        key={actualIdx}
                        data-global-offset={globalOffset}
                        onMouseDown={(e) => handleByteMouseDown(globalOffset, e)}
                        onMouseEnter={(e) => {
                          handleByteMouseEnter(globalOffset);
                          if (pat) {
                            const rect = e.currentTarget.getBoundingClientRect();
                            setHoveredPattern({
                              pattern: pat.pattern,
                              start: currentPage * PAGE_SIZE + pat.start,
                              end: currentPage * PAGE_SIZE + pat.end,
                              hexSnippet: hexStr,
                              x: rect.left + rect.width / 2,
                              y: rect.top,
                            });
                          }
                        }}
                        onMouseLeave={() => {
                          handleByteMouseLeave();
                          setHoveredPattern(null);
                        }}
                        style={{
                          backgroundColor: isSelected
                            ? '#2563eb'
                            : isMatch
                            ? '#fef08a'
                            : isHovered
                            ? '#e0e7ff'
                            : pat
                            ? `${pat.pattern.color}33`
                            : undefined,
                          borderBottom: !isSelected && pat ? `2px solid ${pat.pattern.color}` : undefined,
                        }}
                        className={`inline-block w-6 text-center rounded px-0.5 cursor-pointer select-none transition-colors ${
                          isSelected
                            ? 'bg-blue-600 text-white font-bold ring-1 ring-blue-400 shadow-xs z-1'
                            : isHovered
                            ? 'ring-2 ring-indigo-500 text-indigo-950 font-bold z-1'
                            : byteVal === 0
                            ? 'text-slate-400 font-medium'
                            : 'text-slate-800 font-medium'
                        }`}
                        title={`Offset 0x${globalOffset.toString(16).toUpperCase()} (${globalOffset}): ${byteVal} (0x${hexStr})`}
                      >
                        {byteVal}
                      </span>
                    );
                  })}
                </div>

                {/* ASCII */}
                <div className="w-36 text-right pr-2 select-none tracking-widest text-[11px] font-mono">
                  {Array.from(r.bytes).map((b, bIdx) => {
                    const pageIdx = r.startIndex + bIdx;
                    const globalOffset = r.offsetNum + bIdx;
                    const pat = getPatternForByte(pageIdx);
                    const isMatch = isSearchMatchByte(pageIdx);
                    const isPrintable = b >= 32 && b <= 126;
                    const isSelected =
                      selectionRange !== null &&
                      globalOffset >= selectionRange.start &&
                      globalOffset < selectionRange.end;
                    const isHovered = hoveredByteGlobal === globalOffset;

                    return (
                      <span
                        key={bIdx}
                        data-global-offset={globalOffset}
                        onMouseDown={(e) => handleByteMouseDown(globalOffset, e)}
                        onMouseEnter={(e) => {
                          handleByteMouseEnter(globalOffset);
                          if (pat) {
                            const rect = e.currentTarget.getBoundingClientRect();
                            setHoveredPattern({
                              pattern: pat.pattern,
                              start: currentPage * PAGE_SIZE + pat.start,
                              end: currentPage * PAGE_SIZE + pat.end,
                              hexSnippet: b.toString(16).padStart(2, '0').toUpperCase(),
                              x: rect.left + rect.width / 2,
                              y: rect.top,
                            });
                          }
                        }}
                        onMouseLeave={() => {
                          handleByteMouseLeave();
                          setHoveredPattern(null);
                        }}
                        style={{
                          backgroundColor: isSelected
                            ? '#2563eb'
                            : isMatch
                            ? '#fef08a'
                            : isHovered
                            ? '#e0e7ff'
                            : pat
                            ? `${pat.pattern.color}33`
                            : undefined,
                          color: isSelected
                            ? '#ffffff'
                            : pat
                            ? pat.pattern.color
                            : isPrintable
                            ? '#0f172a'
                            : '#64748b',
                        }}
                        className={`inline-block px-[1px] rounded-xs cursor-pointer select-none transition-colors ${
                          isSelected
                            ? 'bg-blue-600 text-white font-bold ring-1 ring-blue-400 z-1'
                            : isHovered
                            ? 'ring-2 ring-indigo-500 text-indigo-950 font-bold z-1'
                            : ''
                        }`}
                        title={`Offset 0x${globalOffset.toString(16).toUpperCase()} (${globalOffset}): '${isPrintable ? String.fromCharCode(b) : '.'}'`}
                      >
                        {isPrintable ? String.fromCharCode(b) : '.'}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        /* Digital Detective Forensic Hex View (Compact 16-Byte Layout) */
        <div
          onMouseUp={handleContainerMouseUp}
          className="border border-slate-200 rounded-2xl overflow-hidden bg-white max-h-[500px] overflow-y-auto font-mono text-[11px]"
        >
          {/* Header */}
          <div className="sticky top-0 bg-slate-100 border-b border-slate-200 px-3 py-1.5 flex text-[10px] font-bold text-slate-600 uppercase tracking-wider select-none z-10">
            <span className="w-24 shrink-0">Offset</span>
            <span className="flex-1 min-w-[370px]">
              00 01 02 03 04 05 06 07&nbsp;&nbsp;08 09 0A 0B 0C 0D 0E 0F
            </span>
            <span className="w-36 text-right pr-2">Decoded Text</span>
          </div>

          <div className="divide-y divide-slate-100">
            {hexRows.map((r) => (
              <div
                key={r.offsetNum}
                className="flex items-center px-3 py-0.5 hover:bg-indigo-50/40 transition-colors font-mono text-[11px] leading-4 select-none"
              >
                {/* Column 1: Offset (Digital Detective style 00000000:) */}
                <span className="w-24 shrink-0 text-slate-600 select-none font-semibold">
                  {r.offsetHex}:
                </span>

                {/* Column 2: 16 Hex Bytes with 2-space divider between 7 and 8 */}
                <div className="flex-1 min-w-[370px] flex items-center space-x-1.5">
                  {/* Bytes 0 to 7 */}
                  <div className="flex items-center space-x-1">
                    {Array.from({ length: 8 }).map((_, byteIdx) => {
                      if (byteIdx >= r.bytes.length) {
                        return <span key={byteIdx} className="inline-block w-4 text-transparent">..</span>;
                      }
                      const pageIdx = r.startIndex + byteIdx;
                      const globalOffset = r.offsetNum + byteIdx;
                      const byteVal = r.bytes[byteIdx];
                      const hexStr = byteVal.toString(16).padStart(2, '0').toUpperCase();
                      const pat = getPatternForByte(pageIdx);
                      const isMatch = isSearchMatchByte(pageIdx);
                      const isSelected =
                        selectionRange !== null &&
                        globalOffset >= selectionRange.start &&
                        globalOffset < selectionRange.end;
                      const isHovered = hoveredByteGlobal === globalOffset;

                      return (
                        <span
                          key={byteIdx}
                          data-global-offset={globalOffset}
                          onMouseDown={(e) => handleByteMouseDown(globalOffset, e)}
                          onMouseEnter={(e) => {
                            handleByteMouseEnter(globalOffset);
                            if (pat) {
                              const rect = e.currentTarget.getBoundingClientRect();
                              setHoveredPattern({
                                pattern: pat.pattern,
                                start: currentPage * PAGE_SIZE + pat.start,
                                end: currentPage * PAGE_SIZE + pat.end,
                                hexSnippet: hexStr,
                                x: rect.left + rect.width / 2,
                                y: rect.top,
                              });
                            }
                          }}
                          onMouseLeave={() => {
                            handleByteMouseLeave();
                            setHoveredPattern(null);
                          }}
                          style={{
                            backgroundColor: isSelected
                              ? '#2563eb'
                              : isMatch
                              ? '#fef08a'
                              : isHovered
                              ? '#e0e7ff'
                              : pat
                              ? `${pat.pattern.color}33`
                              : undefined,
                            borderBottom: !isSelected && pat ? `2px solid ${pat.pattern.color}` : undefined,
                          }}
                          className={`inline-block px-0.5 rounded cursor-pointer select-none transition-colors ${
                            isSelected
                              ? 'bg-blue-600 text-white font-bold ring-1 ring-blue-400 shadow-xs z-1'
                              : isHovered
                              ? 'ring-2 ring-indigo-500 text-indigo-950 font-bold z-1'
                              : byteVal === 0
                              ? 'text-slate-500 font-medium'
                              : byteVal >= 32 && byteVal <= 126
                              ? 'text-slate-900 font-bold'
                              : 'text-slate-800 font-semibold'
                          }`}
                          title={`Offset 0x${globalOffset.toString(16).toUpperCase()} (${globalOffset}): ${byteVal} (0x${hexStr})`}
                        >
                          {hexStr}
                        </span>
                      );
                    })}
                  </div>

                  <span className="text-slate-400 select-none">&nbsp;</span>

                  {/* Bytes 8 to 15 */}
                  <div className="flex items-center space-x-1">
                    {Array.from({ length: 8 }).map((_, byteIdx) => {
                      const actualIdx = byteIdx + 8;
                      if (actualIdx >= r.bytes.length) {
                        return <span key={actualIdx} className="inline-block w-4 text-transparent">..</span>;
                      }
                      const pageIdx = r.startIndex + actualIdx;
                      const globalOffset = r.offsetNum + actualIdx;
                      const byteVal = r.bytes[actualIdx];
                      const hexStr = byteVal.toString(16).padStart(2, '0').toUpperCase();
                      const pat = getPatternForByte(pageIdx);
                      const isMatch = isSearchMatchByte(pageIdx);
                      const isSelected =
                        selectionRange !== null &&
                        globalOffset >= selectionRange.start &&
                        globalOffset < selectionRange.end;
                      const isHovered = hoveredByteGlobal === globalOffset;

                      return (
                        <span
                          key={actualIdx}
                          data-global-offset={globalOffset}
                          onMouseDown={(e) => handleByteMouseDown(globalOffset, e)}
                          onMouseEnter={(e) => {
                            handleByteMouseEnter(globalOffset);
                            if (pat) {
                              const rect = e.currentTarget.getBoundingClientRect();
                              setHoveredPattern({
                                pattern: pat.pattern,
                                start: currentPage * PAGE_SIZE + pat.start,
                                end: currentPage * PAGE_SIZE + pat.end,
                                hexSnippet: hexStr,
                                x: rect.left + rect.width / 2,
                                y: rect.top,
                              });
                            }
                          }}
                          onMouseLeave={() => {
                            handleByteMouseLeave();
                            setHoveredPattern(null);
                          }}
                          style={{
                            backgroundColor: isSelected
                              ? '#2563eb'
                              : isMatch
                              ? '#fef08a'
                              : isHovered
                              ? '#e0e7ff'
                              : pat
                              ? `${pat.pattern.color}33`
                              : undefined,
                            borderBottom: !isSelected && pat ? `2px solid ${pat.pattern.color}` : undefined,
                          }}
                          className={`inline-block px-0.5 rounded cursor-pointer select-none transition-colors ${
                            isSelected
                              ? 'bg-blue-600 text-white font-bold ring-1 ring-blue-400 shadow-xs z-1'
                              : isHovered
                              ? 'ring-2 ring-indigo-500 text-indigo-950 font-bold z-1'
                              : byteVal === 0
                              ? 'text-slate-500 font-medium'
                              : byteVal >= 32 && byteVal <= 126
                              ? 'text-slate-900 font-bold'
                              : 'text-slate-800 font-semibold'
                          }`}
                          title={`Offset 0x${globalOffset.toString(16).toUpperCase()} (${globalOffset}): ${byteVal} (0x${hexStr})`}
                        >
                          {hexStr}
                        </span>
                      );
                    })}
                  </div>
                </div>

                {/* Column 3: Decoded Text (Compact ASCII with '.' for non-printable) */}
                <div className="w-36 text-right pr-2 select-none tracking-widest text-[11px] font-mono">
                  {Array.from(r.bytes).map((b, bIdx) => {
                    const pageIdx = r.startIndex + bIdx;
                    const globalOffset = r.offsetNum + bIdx;
                    const pat = getPatternForByte(pageIdx);
                    const isMatch = isSearchMatchByte(pageIdx);
                    const isPrintable = b >= 32 && b <= 126;
                    const isSelected =
                      selectionRange !== null &&
                      globalOffset >= selectionRange.start &&
                      globalOffset < selectionRange.end;
                    const isHovered = hoveredByteGlobal === globalOffset;

                    return (
                      <span
                        key={bIdx}
                        data-global-offset={globalOffset}
                        onMouseDown={(e) => handleByteMouseDown(globalOffset, e)}
                        onMouseEnter={(e) => {
                          handleByteMouseEnter(globalOffset);
                          if (pat) {
                            const rect = e.currentTarget.getBoundingClientRect();
                            setHoveredPattern({
                              pattern: pat.pattern,
                              start: currentPage * PAGE_SIZE + pat.start,
                              end: currentPage * PAGE_SIZE + pat.end,
                              hexSnippet: b.toString(16).padStart(2, '0').toUpperCase(),
                              x: rect.left + rect.width / 2,
                              y: rect.top,
                            });
                          }
                        }}
                        onMouseLeave={() => {
                          handleByteMouseLeave();
                          setHoveredPattern(null);
                        }}
                        style={{
                          backgroundColor: isSelected
                            ? '#2563eb'
                            : isMatch
                            ? '#fef08a'
                            : isHovered
                            ? '#e0e7ff'
                            : pat
                            ? `${pat.pattern.color}33`
                            : undefined,
                          color: isSelected
                            ? '#ffffff'
                            : pat
                            ? pat.pattern.color
                            : isPrintable
                            ? '#0f172a'
                            : '#64748b',
                        }}
                        className={`inline-block px-[1px] rounded-xs cursor-pointer select-none transition-colors ${
                          isSelected
                            ? 'bg-blue-600 text-white font-bold ring-1 ring-blue-400 z-1'
                            : isHovered
                            ? 'ring-2 ring-indigo-500 text-indigo-950 font-bold z-1'
                            : ''
                        }`}
                        title={`Offset 0x${globalOffset.toString(16).toUpperCase()} (${globalOffset}): '${isPrintable ? String.fromCharCode(b) : '.'}'`}
                      >
                        {isPrintable ? String.fromCharCode(b) : '.'}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Hover Tooltip for Pattern Highlighting */}
      {hoveredPattern && (
        <div
          className="fixed z-50 bg-slate-900/95 backdrop-blur-md text-white p-3.5 rounded-2xl shadow-2xl border border-slate-700/80 max-w-md pointer-events-none transition-all text-xs"
          style={{
            left: `${Math.max(160, Math.min(typeof window !== 'undefined' ? window.innerWidth - 180 : 800, hoveredPattern.x))}px`,
            top: hoveredPattern.y < 180
              ? `${hoveredPattern.y + 36}px`
              : `${Math.max(12, hoveredPattern.y - 20)}px`,
            transform: hoveredPattern.y < 180 ? 'translate(-50%, 0)' : 'translate(-50%, -100%)',
            pointerEvents: 'none',
          }}
        >
          <div className="flex items-center justify-between gap-2 mb-1.5 pb-1.5 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <span
                className="w-2.5 h-2.5 rounded-full shrink-0"
                style={{ backgroundColor: hoveredPattern.pattern.color }}
              />
              <span className="font-bold text-white text-xs">
                {hoveredPattern.pattern.name}
              </span>
            </div>
            <span
              className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider text-white shrink-0"
              style={{ backgroundColor: hoveredPattern.pattern.color }}
            >
              {hoveredPattern.pattern.structure_type || 'structure'}
            </span>
          </div>

          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-300 mb-1.5">
            <span className="bg-slate-800 px-1.5 py-0.5 rounded text-amber-300">
              Offset: 0x{hoveredPattern.start.toString(16).padStart(8, '0').toUpperCase()}
              {hoveredPattern.end - hoveredPattern.start > 1 && ` - 0x${(hoveredPattern.end - 1).toString(16).padStart(8, '0').toUpperCase()}`}
            </span>
            <span className="bg-slate-800 px-1.5 py-0.5 rounded text-slate-300">
              Length: {hoveredPattern.end - hoveredPattern.start}B
            </span>
            <span className="bg-slate-800 px-1.5 py-0.5 rounded text-indigo-300 truncate">
              {hoveredPattern.pattern.category}
            </span>
          </div>

          <p className="text-[11px] text-slate-300 leading-relaxed mb-2 font-sans">
            {hoveredPattern.pattern.description}
          </p>

          <div className="text-[10px] font-mono text-slate-400 bg-slate-950/80 px-2 py-1.5 rounded-lg border border-slate-800/80 flex items-center justify-between gap-2">
            <span className="text-slate-400">Pattern ({hoveredPattern.pattern.type}):</span>
            <span className="text-emerald-400 font-semibold truncate">{hoveredPattern.pattern.pattern}</span>
          </div>
        </div>
      )}
    </div>
  );
};
