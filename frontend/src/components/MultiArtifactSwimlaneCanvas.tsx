import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  Search,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ArrowRight,
  AlertTriangle,
  FileCode,
  Mail,
  FileSpreadsheet,
  Terminal,
  Activity,
  Layers,
  ChevronRight,
  X,
  Radio,
  SlidersHorizontal,
  Info,
  Shield,
  FileText
} from 'lucide-react';
import { ForensicTimelineEvent, ForensicSwimlane, ForensicCausalityLink } from '../types';
import { formatTimestamp } from '../utils/formatters';

interface MultiArtifactSwimlaneCanvasProps {
  events: ForensicTimelineEvent[];
  swimlanes?: ForensicSwimlane[];
  causalityLinks?: ForensicCausalityLink[];
  jobId: string;
  isSuperTimeline?: boolean;
  onRemoveLane?: (laneId: string) => void;
}

const KILL_CHAIN_PHASE_CONFIG: Record<
  string,
  { label: string; bg: string; border: string; text: string; dot: string; description: string }
> = {
  initial_access: {
    label: 'Initial Access',
    bg: 'bg-sky-50',
    border: 'border-sky-300',
    text: 'text-sky-800',
    dot: 'bg-sky-500',
    description: 'Techniques used to gain an initial foothold (phishing, drive-by, attachments)'
  },
  execution: {
    label: 'Execution',
    bg: 'bg-indigo-50',
    border: 'border-indigo-300',
    text: 'text-indigo-800',
    dot: 'bg-indigo-500',
    description: 'Adversary-controlled code execution (macros, scripts, process spawn 4688)'
  },
  persistence: {
    label: 'Persistence',
    bg: 'bg-amber-50',
    border: 'border-amber-300',
    text: 'text-amber-800',
    dot: 'bg-amber-500',
    description: 'Techniques to maintain access across restarts (services 7045, scheduled tasks 4698)'
  },
  privilege_escalation: {
    label: 'Privilege Escalation',
    bg: 'bg-orange-50',
    border: 'border-orange-300',
    text: 'text-orange-800',
    dot: 'bg-orange-500',
    description: 'Elevating privileges to SYSTEM or Administrator (token impersonation, UAC bypass)'
  },
  defense_evasion: {
    label: 'Defense Evasion',
    bg: 'bg-rose-50',
    border: 'border-rose-300',
    text: 'text-rose-800',
    dot: 'bg-rose-500',
    description: 'Avoiding detection, clearing logs (1102/104), timestomping, anti-debug hooks'
  },
  credential_access: {
    label: 'Credential Access',
    bg: 'bg-purple-50',
    border: 'border-purple-300',
    text: 'text-purple-800',
    dot: 'bg-purple-500',
    description: 'Stealing credentials, LSASS dumps, brute forcing passphrases'
  },
  discovery: {
    label: 'Discovery',
    bg: 'bg-emerald-50',
    border: 'border-emerald-300',
    text: 'text-emerald-800',
    dot: 'bg-emerald-500',
    description: 'Gaining knowledge about the system, internal network, and file system'
  },
  lateral_movement: {
    label: 'Lateral Movement',
    bg: 'bg-teal-50',
    border: 'border-teal-300',
    text: 'text-teal-800',
    dot: 'bg-teal-500',
    description: 'Accessing and controlling remote systems on the network'
  },
  command_and_control: {
    label: 'Command & Control',
    bg: 'bg-blue-50',
    border: 'border-blue-300',
    text: 'text-blue-800',
    dot: 'bg-blue-500',
    description: 'Communication with adversary-controlled infrastructure (beacons, DNS queries)'
  },
  threat_intel: {
    label: 'Threat Intelligence',
    bg: 'bg-slate-50',
    border: 'border-slate-300',
    text: 'text-slate-800',
    dot: 'bg-slate-500',
    description: 'Historical submissions and intelligence sightings across global threat feeds'
  }
};

const ARTIFACT_ICON_CONFIG: Record<string, (c: string) => React.ReactNode> = {
  email: (c) => <Mail className={c} />,
  office: (c) => <FileSpreadsheet className={c} />,
  pdf: (c) => <FileText className={c} />,
  binary: (c) => <FileCode className={c} />,
  script: (c) => <Terminal className={c} />,
  evtx: (c) => <Shield className={c} />,
  pcap: (c) => <Activity className={c} />,
  anomaly: (c) => <AlertTriangle className={c} />,
  threat_intel: (c) => <Radio className={c} />,
  filesystem: (c) => <Layers className={c} />
};

export const MultiArtifactSwimlaneCanvas: React.FC<MultiArtifactSwimlaneCanvasProps> = ({
  events,
  swimlanes: propSwimlanes,
  causalityLinks = [],
  jobId: _jobId,
  isSuperTimeline = false,
  onRemoveLane
}) => {
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedPhase, setSelectedPhase] = useState<string>('all');
  const [showCausalityVectors, setShowCausalityVectors] = useState<boolean>(true);
  const [anomaliesOnly, setAnomaliesOnly] = useState<boolean>(false);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [hoveredEventId, setHoveredEventId] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);

  // Fallback swimlanes if none provided
  const activeSwimlanes = useMemo(() => {
    if (propSwimlanes && propSwimlanes.length > 0) {
      return propSwimlanes;
    }
    const distinctFiles = Array.from(new Set(events.map((e) => e.filename || 'Artifact Activity')));
    if (distinctFiles.length > 1) {
      return distinctFiles.map((fn) => ({
        id: fn,
        title: fn,
        artifact_type: 'filesystem',
        event_count: events.filter((e) => e.filename === fn).length
      }));
    }
    // Subsystem lanes for single artifact
    return [
      { id: 'delivery', title: 'Initial Ingestion & Delivery', artifact_type: 'email', event_count: 1 },
      { id: 'execution', title: 'Host Execution & Processes', artifact_type: 'binary', event_count: 1 },
      { id: 'persistence', title: 'Persistence & Privileges', artifact_type: 'system', event_count: 1 },
      { id: 'network', title: 'Network Communications (C2)', artifact_type: 'pcap', event_count: 1 },
      { id: 'defense_evasion', title: 'Anti-Forensics & Tampering', artifact_type: 'anomaly', event_count: 1 }
    ];
  }, [propSwimlanes, events]);

  // Chronologically sorted events
  const sortedEvents = useMemo(() => {
    return [...events].sort((a, b) => a.epoch - b.epoch);
  }, [events]);

  // Filtering
  const filteredEvents = useMemo(() => {
    return sortedEvents.filter((e) => {
      if (anomaliesOnly && !e.is_anomaly) return false;
      if (selectedPhase !== 'all' && e.kill_chain_phase !== selectedPhase) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matches =
          e.title.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          e.source.toLowerCase().includes(q) ||
          e.event_type.toLowerCase().includes(q) ||
          (e.filename && e.filename.toLowerCase().includes(q));
        if (!matches) return false;
      }
      return true;
    });
  }, [sortedEvents, anomaliesOnly, selectedPhase, searchQuery]);

  // Map each event to an X coordinate
  // We use indexed distribution with spacing for readability while preserving chronological sequence
  const LANE_HEADER_WIDTH = 260;
  const NODE_SPACING = Math.max(180, 240 * zoomLevel);
  const LANE_HEIGHT = 110;
  const PADDING_LEFT = 140;
  const PADDING_TOP = 60;

  // Calculate layout coordinates for each event
  const eventPositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number; laneIndex: number }> = {};
    if (filteredEvents.length === 0) return positions;

    filteredEvents.forEach((ev, idx) => {
      const eid = ev.id || `evt_${idx}`;
      // Find swimlane index
      let laneIdx = activeSwimlanes.findIndex((l) => l.id === ev.swimlane_id || l.id === ev.filename);
      if (laneIdx === -1) laneIdx = 0;

      const x = PADDING_LEFT + idx * NODE_SPACING;
      const y = PADDING_TOP + laneIdx * LANE_HEIGHT + LANE_HEIGHT / 2;

      positions[eid] = { x, y, laneIndex: laneIdx };
    });

    return positions;
  }, [filteredEvents, activeSwimlanes, NODE_SPACING]);

  // Total canvas dimensions
  const canvasWidth = Math.max(
    1000,
    PADDING_LEFT + filteredEvents.length * NODE_SPACING + 240
  );
  const canvasHeight = PADDING_TOP + activeSwimlanes.length * LANE_HEIGHT + 40;

  // Selected event object
  const selectedEvent = useMemo(() => {
    if (!selectedEventId) return null;
    return sortedEvents.find((e) => e.id === selectedEventId) || null;
  }, [selectedEventId, sortedEvents]);

  // Causality links related to selected or hovered event
  const activeFocusId = hoveredEventId || selectedEventId;
  const relatedLinkIds = useMemo(() => {
    if (!activeFocusId) return new Set<string>();
    const set = new Set<string>();
    causalityLinks.forEach((l) => {
      if (l.source_id === activeFocusId || l.target_id === activeFocusId) {
        set.add(l.id);
      }
    });
    return set;
  }, [activeFocusId, causalityLinks]);

  // Upstream & Downstream events for selected event
  const upstreamEvents = useMemo(() => {
    if (!selectedEventId) return [];
    const sourceIds = causalityLinks
      .filter((l) => l.target_id === selectedEventId)
      .map((l) => l.source_id);
    return sortedEvents.filter((e) => e.id && sourceIds.includes(e.id));
  }, [selectedEventId, causalityLinks, sortedEvents]);

  const downstreamEvents = useMemo(() => {
    if (!selectedEventId) return [];
    const targetIds = causalityLinks
      .filter((l) => l.source_id === selectedEventId)
      .map((l) => l.target_id);
    return sortedEvents.filter((e) => e.id && targetIds.includes(e.id));
  }, [selectedEventId, causalityLinks, sortedEvents]);

  // Available phases with counts
  const phaseCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    sortedEvents.forEach((e) => {
      const p = e.kill_chain_phase || 'initial_access';
      counts[p] = (counts[p] || 0) + 1;
    });
    return counts;
  }, [sortedEvents]);

  // Auto-scroll to selected event
  useEffect(() => {
    if (selectedEventId && eventPositions[selectedEventId] && containerRef.current) {
      const pos = eventPositions[selectedEventId];
      const targetScroll = pos.x - 300;
      containerRef.current.scrollTo({ left: Math.max(0, targetScroll), behavior: 'smooth' });
    }
  }, [selectedEventId, eventPositions]);

  return (
    <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-7 shadow-xs space-y-5">
      {/* Header and Controls */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-5 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Activity className="w-5 h-5 text-indigo-600" />
              Interactive Multi-Artifact Swimlane Canvas
            </h3>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
              MITRE ATT&CK Kill-Chain Reconstructor
            </span>
            {isSuperTimeline && (
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-50 text-amber-800 border border-amber-300">
                Unified Super-Timeline Mode
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-1 leading-relaxed">
            Continuous chronological timeline with artifact-segregated swimlanes, directed causality vector curves, and MITRE ATT&CK tactic progression.
          </p>
        </div>

        {/* Toolbar Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Search Bar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search event, process, PID, hash..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 w-52"
            />
          </div>

          {/* Anomalies Only Toggle */}
          <button
            onClick={() => setAnomaliesOnly(!anomaliesOnly)}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors flex items-center gap-1.5 border cursor-pointer ${
              anomaliesOnly
                ? 'bg-rose-50 text-rose-700 border-rose-300 font-bold shadow-xs'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-500" />
            <span>Anomalies Only</span>
          </button>

          {/* Toggle Causality Vectors */}
          <button
            onClick={() => setShowCausalityVectors(!showCausalityVectors)}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors flex items-center gap-1.5 border cursor-pointer ${
              showCausalityVectors
                ? 'bg-indigo-50 text-indigo-700 border-indigo-300 shadow-xs'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            <Radio className="w-3.5 h-3.5 text-indigo-500" />
            <span>Causality Vectors ({causalityLinks.length})</span>
          </button>

          {/* Zoom In / Out / Reset */}
          <div className="flex items-center border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs">
            <button
              onClick={() => setZoomLevel((z) => Math.max(0.6, z - 0.2))}
              className="p-1.5 text-slate-600 hover:bg-slate-50 transition-colors cursor-pointer border-r border-slate-200"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <span className="px-2 text-[11px] font-mono font-bold text-slate-700 select-none">
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => setZoomLevel((z) => Math.min(2.5, z + 0.2))}
              className="p-1.5 text-slate-600 hover:bg-slate-50 transition-colors cursor-pointer border-l border-slate-200"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="p-1.5 text-slate-600 hover:bg-slate-50 transition-colors cursor-pointer border-l border-slate-200"
              title="Reset Zoom"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Kill-Chain Phase Filter Pills */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
        <button
          onClick={() => setSelectedPhase('all')}
          className={`px-3 py-1 rounded-xl text-xs font-semibold shrink-0 cursor-pointer border transition-colors ${
            selectedPhase === 'all'
              ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
              : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
          }`}
        >
          All Tactics ({sortedEvents.length})
        </button>
        {Object.entries(KILL_CHAIN_PHASE_CONFIG).map(([phase, cfg]) => {
          const count = phaseCounts[phase] || 0;
          if (count === 0) return null;
          const isSelected = selectedPhase === phase;
          return (
            <button
              key={phase}
              onClick={() => setSelectedPhase(phase)}
              className={`px-2.5 py-1 rounded-xl text-xs font-semibold shrink-0 cursor-pointer border transition-colors flex items-center gap-1.5 ${
                isSelected
                  ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                  : `${cfg.bg} ${cfg.text} ${cfg.border} hover:opacity-90`
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
              <span>{cfg.label}</span>
              <span className="font-mono text-[10px] opacity-75">({count})</span>
            </button>
          );
        })}
      </div>

      {/* Main Swimlane Canvas Container */}
      <div className="relative border border-slate-200 rounded-2xl bg-white overflow-hidden shadow-inner flex">
        {/* Left Fixed Swimlane Headers */}
        <div
          className="shrink-0 border-r border-slate-200 bg-slate-50/90 z-10 flex flex-col"
          style={{ width: `${LANE_HEADER_WIDTH}px` }}
        >
          {/* Header Corner Spacer (aligns with X-axis timeline ruler) */}
          <div
            className="h-[60px] border-b border-slate-200 px-4 flex items-center justify-between bg-slate-100/70"
          >
            <span className="text-[11px] font-bold text-slate-600 uppercase tracking-wider flex items-center gap-1.5">
              <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
              Artifact Lanes ({activeSwimlanes.length})
            </span>
          </div>

          {/* Swimlane Header Rows */}
          {activeSwimlanes.map((lane, idx) => {
            const iconFn = ARTIFACT_ICON_CONFIG[lane.artifact_type] || ARTIFACT_ICON_CONFIG.filesystem;
            return (
              <div
                key={lane.id}
                className={`px-4 flex flex-col justify-center border-b border-slate-200 transition-colors ${
                  idx % 2 === 0 ? 'bg-white' : 'bg-slate-50/80'
                }`}
                style={{ height: `${LANE_HEIGHT}px` }}
              >
                <div className="flex items-center justify-between gap-1 mb-1">
                  <div className="flex items-center gap-2 truncate">
                    <div className="p-1.5 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-700 shrink-0">
                      {iconFn('w-3.5 h-3.5')}
                    </div>
                    <span
                      className="text-xs font-bold text-slate-900 truncate"
                      title={lane.title}
                    >
                      {lane.title}
                    </span>
                  </div>
                  {onRemoveLane && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onRemoveLane(lane.id);
                      }}
                      className="p-1 rounded-md text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors cursor-pointer shrink-0"
                      title={`Remove ${lane.title} from timeline`}
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
                <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
                  <span className="uppercase px-1.5 py-0.5 rounded bg-slate-200/70 text-slate-700 font-sans font-semibold">
                    {lane.artifact_type}
                  </span>
                  <span>•</span>
                  <span>{lane.event_count} event{lane.event_count !== 1 ? 's' : ''}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Scrollable Canvas Area (X-Axis Ruler + Nodes + Vector Curves) */}
        <div
          ref={containerRef}
          className="flex-1 overflow-x-auto overflow-y-hidden relative bg-dot-grid"
          style={{ minHeight: `${canvasHeight}px` }}
        >
          {/* Top Continuous Chronological Timeline Ruler (X-Axis) */}
          <div
            className="sticky top-0 left-0 h-[60px] border-b border-slate-200 bg-white/95 backdrop-blur-xs z-10 flex items-center px-4"
            style={{ width: `${canvasWidth}px` }}
          >
            {filteredEvents.map((ev, idx) => {
              const pos = eventPositions[ev.id || `evt_${idx}`];
              if (!pos) return null;
              return (
                <div
                  key={idx}
                  className="absolute flex flex-col items-center -translate-x-1/2 pointer-events-none"
                  style={{ left: `${pos.x}px`, top: '10px' }}
                >
                  <span className="font-mono text-[10px] font-bold text-slate-700">
                    {formatTimestamp(ev.timestamp)}
                  </span>
                  <div className="w-0.5 h-2 bg-slate-300 mt-1" />
                </div>
              );
            })}
          </div>

          {/* SVG Overlay for Swimlane Grid & Directed Causality Vectors */}
          <svg
            className="absolute top-0 left-0 pointer-events-none"
            width={canvasWidth}
            height={canvasHeight}
            style={{ zIndex: 1 }}
          >
            <defs>
              {/* Arrowhead marker for directed causality vectors */}
              <marker
                id="causality-arrow"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#6366f1" />
              </marker>
              <marker
                id="causality-arrow-active"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="8"
                markerHeight="8"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
              </marker>
            </defs>

            {/* Horizontal Swimlane Guide Lines */}
            {activeSwimlanes.map((_, idx) => (
              <line
                key={idx}
                x1={0}
                y1={PADDING_TOP + (idx + 1) * LANE_HEIGHT}
                x2={canvasWidth}
                y2={PADDING_TOP + (idx + 1) * LANE_HEIGHT}
                stroke="#e2e8f0"
                strokeWidth={1}
                strokeDasharray="4,4"
              />
            ))}

            {/* Vertical Time Guidelines */}
            {filteredEvents.map((ev, idx) => {
              const pos = eventPositions[ev.id || `evt_${idx}`];
              if (!pos) return null;
              return (
                <line
                  key={`vline_${idx}`}
                  x1={pos.x}
                  y1={PADDING_TOP}
                  x2={pos.x}
                  y2={canvasHeight}
                  stroke="#f1f5f9"
                  strokeWidth={1}
                />
              );
            })}

            {/* Directed Causality Vector Curves */}
            {showCausalityVectors &&
              causalityLinks.map((link) => {
                const srcPos = eventPositions[link.source_id];
                const dstPos = eventPositions[link.target_id];
                if (!srcPos || !dstPos) return null;

                const isLinkActive = relatedLinkIds.has(link.id);
                const isDimmed = activeFocusId && !isLinkActive;

                // Bezier control points for smooth curving
                const dx = dstPos.x - srcPos.x;
                const cx1 = srcPos.x + dx * 0.45;
                const cy1 = srcPos.y;
                const cx2 = dstPos.x - dx * 0.45;
                const cy2 = dstPos.y;

                const pathData = `M ${srcPos.x} ${srcPos.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${dstPos.x} ${dstPos.y}`;

                return (
                  <g key={link.id} className="transition-opacity duration-200">
                    <path
                      d={pathData}
                      fill="none"
                      stroke={isLinkActive ? '#f43f5e' : '#6366f1'}
                      strokeWidth={isLinkActive ? 3.5 : 2}
                      strokeDasharray={isLinkActive ? undefined : '5,5'}
                      strokeOpacity={isDimmed ? 0.15 : isLinkActive ? 1 : 0.65}
                      markerEnd={isLinkActive ? 'url(#causality-arrow-active)' : 'url(#causality-arrow)'}
                    />
                  </g>
                );
              })}
          </svg>

          {/* Interactive Event Nodes */}
          <div className="relative" style={{ width: `${canvasWidth}px`, height: `${canvasHeight}px`, zIndex: 2 }}>
            {filteredEvents.map((ev, idx) => {
              const eid = ev.id || `evt_${idx}`;
              const pos = eventPositions[eid];
              if (!pos) return null;

              const isSelected = selectedEventId === eid;
              const isHovered = hoveredEventId === eid;
              const phaseKey = ev.kill_chain_phase || 'initial_access';
              const phaseConfig = KILL_CHAIN_PHASE_CONFIG[phaseKey] || KILL_CHAIN_PHASE_CONFIG.initial_access;
              const isAnomaly = ev.is_anomaly;

              return (
                <div
                  key={eid}
                  data-event-id={eid}
                  style={{
                    left: `${pos.x}px`,
                    top: `${pos.y}px`,
                    transform: 'translate(-50%, -50%)'
                  }}
                  className="absolute cursor-pointer group"
                  onClick={() => setSelectedEventId(isSelected ? null : eid)}
                  onMouseEnter={() => setHoveredEventId(eid)}
                  onMouseLeave={() => setHoveredEventId(null)}
                >
                  {/* Pulsing ring for timestomping anomalies */}
                  {isAnomaly && (
                    <span className="absolute -inset-2 rounded-2xl bg-rose-500/20 animate-ping pointer-events-none" />
                  )}

                  {/* Main Event Card Node */}
                  <div
                    className={`relative w-44 p-3 rounded-2xl border transition-all duration-150 select-none shadow-sm ${
                      isSelected
                        ? 'ring-2 ring-indigo-600 border-indigo-600 bg-white shadow-lg scale-105 z-20'
                        : isHovered
                        ? 'border-indigo-400 bg-white shadow-md scale-102 z-10'
                        : `${phaseConfig.bg} ${phaseConfig.border} hover:bg-white`
                    }`}
                  >
                    {/* Top Tactic & Anomaly Badges */}
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      <span
                        className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-md ${phaseConfig.bg} ${phaseConfig.text} border ${phaseConfig.border}`}
                      >
                        {phaseConfig.label}
                      </span>
                      {isAnomaly && (
                        <span className="flex items-center gap-0.5 text-[9px] font-bold text-rose-700 bg-rose-100 border border-rose-300 px-1 py-0.5 rounded">
                          <AlertTriangle className="w-2.5 h-2.5 text-rose-600" />
                          <span>Anomaly</span>
                        </span>
                      )}
                    </div>

                    {/* Event Title */}
                    <div className="text-xs font-bold text-slate-900 leading-tight line-clamp-2">
                      {ev.title}
                    </div>

                    {/* Metadata Subtitle */}
                    <div className="text-[10px] text-slate-500 font-mono mt-1.5 truncate">
                      {ev.source}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Interactive Event Details Side/Bottom Drawer */}
      {selectedEvent && (
        <div className="p-6 bg-slate-50/90 border border-slate-200 rounded-3xl space-y-4 animate-modal-fade">
          <div className="flex items-start justify-between gap-4 pb-3 border-b border-slate-200">
            <div className="flex items-start gap-3">
              <div className="p-2.5 bg-indigo-100 text-indigo-700 rounded-2xl shrink-0 mt-0.5">
                <Info className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h4 className="text-sm font-bold text-slate-900">
                    {selectedEvent.title}
                  </h4>
                  {selectedEvent.is_anomaly && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300">
                      Timestomping / Anomaly
                    </span>
                  )}
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-200 text-slate-700">
                    {selectedEvent.event_type}
                  </span>
                </div>
                <p className="text-xs text-slate-600 mt-1">
                  {selectedEvent.description}
                </p>
              </div>
            </div>

            <button
              onClick={() => setSelectedEventId(null)}
              className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-200/60 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Event Metadata Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <div className="p-3 bg-white rounded-xl border border-slate-200">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-1">
                Timestamp (UTC)
              </span>
              <span className="font-mono font-semibold text-slate-800">
                {selectedEvent.timestamp}
              </span>
            </div>

            <div className="p-3 bg-white rounded-xl border border-slate-200">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-1">
                Kill-Chain Phase
              </span>
              <span className="font-bold text-indigo-700 uppercase">
                {KILL_CHAIN_PHASE_CONFIG[selectedEvent.kill_chain_phase || 'initial_access']?.label || selectedEvent.kill_chain_phase}
              </span>
            </div>

            <div className="p-3 bg-white rounded-xl border border-slate-200">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-1">
                Artifact Source
              </span>
              <span className="font-semibold text-slate-800 truncate block">
                {selectedEvent.filename || selectedEvent.source}
              </span>
            </div>

            <div className="p-3 bg-white rounded-xl border border-slate-200">
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-1">
                Severity Level
              </span>
              <span
                className={`font-bold uppercase ${
                  selectedEvent.severity === 'critical'
                    ? 'text-rose-600'
                    : selectedEvent.severity === 'high'
                    ? 'text-amber-600'
                    : 'text-slate-700'
                }`}
              >
                {selectedEvent.severity}
              </span>
            </div>
          </div>

          {/* Directed Causality Chain Walkers */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            {/* Upstream Causes */}
            <div className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
              <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <ArrowRight className="w-3.5 h-3.5 text-indigo-600 rotate-180" />
                <span>Preceding Event / Upstream Cause ({upstreamEvents.length})</span>
              </span>
              {upstreamEvents.length > 0 ? (
                <div className="space-y-1.5">
                  {upstreamEvents.map((up) => (
                    <button
                      key={up.id}
                      onClick={() => up.id && setSelectedEventId(up.id)}
                      className="w-full text-left p-2.5 bg-slate-50 hover:bg-indigo-50/70 border border-slate-200 hover:border-indigo-300 rounded-xl transition-all cursor-pointer flex items-center justify-between gap-2"
                    >
                      <div className="truncate">
                        <div className="text-xs font-bold text-slate-800 truncate">{up.title}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{up.source}</div>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    </button>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400 italic">No preceding causal events identified.</p>
              )}
            </div>

            {/* Downstream Effects */}
            <div className="p-4 bg-white rounded-2xl border border-slate-200 space-y-2">
              <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <ArrowRight className="w-3.5 h-3.5 text-indigo-600" />
                <span>Triggered Effect / Downstream Activity ({downstreamEvents.length})</span>
              </span>
              {downstreamEvents.length > 0 ? (
                <div className="space-y-1.5">
                  {downstreamEvents.map((down) => (
                    <button
                      key={down.id}
                      onClick={() => down.id && setSelectedEventId(down.id)}
                      className="w-full text-left p-2.5 bg-slate-50 hover:bg-indigo-50/70 border border-slate-200 hover:border-indigo-300 rounded-xl transition-all cursor-pointer flex items-center justify-between gap-2"
                    >
                      <div className="truncate">
                        <div className="text-xs font-bold text-slate-800 truncate">{down.title}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{down.source}</div>
                      </div>
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    </button>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400 italic">No subsequent causal effects identified.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
