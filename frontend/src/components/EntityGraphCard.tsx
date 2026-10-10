import React, { useState, useRef, useEffect, useMemo } from 'react';
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ExternalLink,
  Copy,
  Check,
  Move
} from 'lucide-react';
import { EntityGraphData, EntityGraphNode } from '../types';

interface EntityGraphCardProps {
  graphData?: EntityGraphData | null;
  onSelectJob?: (jobId: string) => void;
}

export const EntityGraphCard: React.FC<EntityGraphCardProps> = ({ graphData, onSelectJob }) => {
  const [selectedNode, setSelectedNode] = useState<EntityGraphNode | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>('all');
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Dragging individual nodes
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const nodeDragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const nodeMouseDownPosRef = useRef<{ x: number; y: number } | null>(null);
  const hasDraggedNodeRef = useRef<boolean>(false);
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Initialize node positions when graphData changes
  useEffect(() => {
    if (graphData?.nodes) {
      const posMap: Record<string, { x: number; y: number }> = {};
      graphData.nodes.forEach(n => {
        if (n.x !== undefined && n.y !== undefined) {
          posMap[n.id] = { x: n.x, y: n.y };
        }
      });
      setNodePositions(posMap);
      setSelectedNode(null);
    }
  }, [graphData]);

  // Smooth mouse scroll wheel & trackpad pinch-zoom centered on cursor
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const handleWheelEvent = (e: WheelEvent) => {
      e.preventDefault();
      const rect = svgEl.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      let factor = 1.0;
      if (e.ctrlKey) {
        // Trackpad pinch-to-zoom
        factor = Math.exp(-e.deltaY * 0.015);
      } else {
        // Standard mouse scroll wheel or two-finger swipe
        factor = e.deltaY < 0 ? 1.12 : 0.89;
      }

      setZoom(prevZoom => {
        const nextZoom = Math.min(3.5, Math.max(0.3, prevZoom * factor));
        setPan(prevPan => {
          const nextPanX = mouseX - (mouseX - prevPan.x) * (nextZoom / prevZoom);
          const nextPanY = mouseY - (mouseY - prevPan.y) * (nextZoom / prevZoom);
          return { x: nextPanX, y: nextPanY };
        });
        return nextZoom;
      });
    };

    svgEl.addEventListener('wheel', handleWheelEvent, { passive: false });
    return () => {
      svgEl.removeEventListener('wheel', handleWheelEvent);
    };
  }, []);

  // Filter nodes
  const filteredNodes = useMemo(() => {
    return (graphData?.nodes ?? []).filter(n => {
      if (activeFilter === 'all') return true;
      if (activeFilter === 'intel') return ['threat_intel', 'threat_signature'].includes(n.type);
      if (activeFilter === 'network') return ['url', 'domain', 'ip', 'geolocation', 'flow', 'protocol', 'asn', 'network', 'organization'].includes(n.type);
      if (activeFilter === 'email') return ['user', 'auth_policy', 'tracking_pixel'].includes(n.type);
      if (activeFilter === 'payloads') return ['embedded_file', 'hash'].includes(n.type);
      if (activeFilter === 'ttps') return ['technique', 'similar_sample'].includes(n.type);
      if (activeFilter === 'trust') return n.type === 'certificate';
      if (activeFilter === 'forensics') return ['log_source', 'user', 'computer', 'ip', 'share', 'process'].includes(n.type);
      return true;
    });
  }, [graphData?.nodes, activeFilter]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return (graphData?.edges ?? []).filter(
      e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)
    );
  }, [graphData?.edges, filteredNodeIds]);

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="bg-white border border-slate-200 rounded-3xl p-10 text-center text-slate-500 shadow-sm">
        <div className="w-14 h-14 rounded-2xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-500 mx-auto mb-3 shadow-inner">
          <Network className="w-7 h-7" />
        </div>
        <h4 className="font-bold text-slate-800 text-sm">No Entity Relationships Available</h4>
        <p className="text-xs text-slate-500 mt-1.5 max-w-md mx-auto leading-relaxed">
          The uploaded artifact does not contain child objects, embedded URLs, digital certificates, or behavioral mappings to graph.
        </p>
      </div>
    );
  }

  // Coordinate conversion helper: client coordinate -> graph space (world)
  const clientToWorld = (clientX: number, clientY: number) => {
    if (!svgRef.current) return { x: 0, y: 0 };
    const rect = svgRef.current.getBoundingClientRect();
    return {
      x: (clientX - rect.left - pan.x) / zoom,
      y: (clientY - rect.top - pan.y) / zoom
    };
  };

  // Canvas Pan Handlers
  const handleSvgMouseDown = (e: React.MouseEvent) => {
    // Only pan if clicking canvas background
    if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).id === 'graph-canvas-bg') {
      setIsPanning(true);
      dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
    }
  };

  // Node Drag Handler (Grabbing individual nodes)
  const handleNodeMouseDown = (node: EntityGraphNode, e: React.MouseEvent) => {
    e.stopPropagation();
    const worldPos = clientToWorld(e.clientX, e.clientY);
    const currNodePos = nodePositions[node.id] || { x: node.x ?? 480, y: node.y ?? 320 };

    nodeDragOffsetRef.current = {
      x: worldPos.x - currNodePos.x,
      y: worldPos.y - currNodePos.y
    };
    nodeMouseDownPosRef.current = { x: e.clientX, y: e.clientY };
    hasDraggedNodeRef.current = false;
    setDraggingNodeId(node.id);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggingNodeId) {
      if (nodeMouseDownPosRef.current) {
        const dx = e.clientX - nodeMouseDownPosRef.current.x;
        const dy = e.clientY - nodeMouseDownPosRef.current.y;
        if (Math.hypot(dx, dy) > 4) {
          hasDraggedNodeRef.current = true;
        }
      }

      const worldPos = clientToWorld(e.clientX, e.clientY);
      const newX = Math.round((worldPos.x - nodeDragOffsetRef.current.x) * 10) / 10;
      const newY = Math.round((worldPos.y - nodeDragOffsetRef.current.y) * 10) / 10;

      setNodePositions(prev => ({
        ...prev,
        [draggingNodeId]: { x: newX, y: newY }
      }));
    } else if (isPanning) {
      setPan({
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y
      });
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggingNodeId(null);
  };

  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Modern Forensic Palette
  const getNodeStyling = (node: EntityGraphNode) => {
    const isRoot = node.id === 'root';
    const isCritical = node.risk === 'critical' || node.risk === 'malicious';
    const isHigh = node.risk === 'high';
    const isWarn = node.risk === 'warning' || node.risk === 'medium';

    if (isCritical) {
      return { fill: '#fff1f2', stroke: '#f43f5e', text: '#9f1239', badge: 'bg-rose-50 text-rose-700 border-rose-200' };
    }
    if (isHigh) {
      return { fill: '#fff7ed', stroke: '#f97316', text: '#9a3412', badge: 'bg-orange-50 text-orange-700 border-orange-200' };
    }
    if (isWarn) {
      return { fill: '#fffbeb', stroke: '#f59e0b', text: '#92400e', badge: 'bg-amber-50 text-amber-700 border-amber-200' };
    }
    if (isRoot) {
      return { fill: '#eef2ff', stroke: '#6366f1', text: '#3730a3', badge: 'bg-indigo-50 text-indigo-700 border-indigo-200' };
    }
    if (node.type === 'threat_intel' || node.type === 'threat_signature') {
      return { fill: '#fef2f2', stroke: '#ef4444', text: '#b91c1c', badge: 'bg-red-50 text-red-700 border-red-200' };
    }
    if (node.type === 'user' || node.type === 'auth_policy') {
      return { fill: '#eff6ff', stroke: '#3b82f6', text: '#1d4ed8', badge: 'bg-blue-50 text-blue-700 border-blue-200' };
    }
    if (node.type === 'domain' || node.type === 'ip') {
      return { fill: '#f0fdfa', stroke: '#0d9488', text: '#115e59', badge: 'bg-teal-50 text-teal-700 border-teal-200' };
    }
    if (node.type === 'asn' || node.type === 'network') {
      return { fill: '#faf5ff', stroke: '#9333ea', text: '#6b21a8', badge: 'bg-purple-50 text-purple-700 border-purple-200' };
    }
    if (node.type === 'organization') {
      return { fill: '#eef2ff', stroke: '#4f46e5', text: '#3730a3', badge: 'bg-indigo-50 text-indigo-700 border-indigo-200' };
    }
    if (node.type === 'geolocation') {
      return { fill: '#ecfdf5', stroke: '#10b981', text: '#065f46', badge: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
    }
    if (node.type === 'url' || node.type === 'tracking_pixel') {
      return { fill: '#f0f9ff', stroke: '#0284c7', text: '#0369a1', badge: 'bg-sky-50 text-sky-700 border-sky-200' };
    }
    if (node.type === 'technique' || node.type === 'similar_sample') {
      return { fill: '#faf5ff', stroke: '#a855f7', text: '#6b21a8', badge: 'bg-purple-50 text-purple-700 border-purple-200' };
    }
    if (node.type === 'certificate') {
      return { fill: '#ecfdf5', stroke: '#059669', text: '#047857', badge: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
    }
    if (node.type === 'protocol') {
      return { fill: '#f0f9ff', stroke: '#0284c7', text: '#0369a1', badge: 'bg-sky-50 text-sky-700 border-sky-200' };
    }
    if (node.type === 'flow') {
      return { fill: '#f5f3ff', stroke: '#8b5cf6', text: '#6d28d9', badge: 'bg-purple-50 text-purple-700 border-purple-200' };
    }
    if (node.type === 'log_source') {
      return { fill: '#fef3c7', stroke: '#d97706', text: '#b45309', badge: 'bg-amber-50 text-amber-800 border-amber-200' };
    }
    if (node.type === 'computer') {
      return { fill: '#f0fdf4', stroke: '#16a34a', text: '#15803d', badge: 'bg-emerald-50 text-emerald-800 border-emerald-200' };
    }
    if (node.type === 'share') {
      return { fill: '#fdf4ff', stroke: '#c026d3', text: '#a21caf', badge: 'bg-fuchsia-50 text-fuchsia-800 border-fuchsia-200' };
    }
    if (node.type === 'process') {
      return { fill: '#fff1f2', stroke: '#e11d48', text: '#be123c', badge: 'bg-rose-50 text-rose-800 border-rose-200' };
    }
    return { fill: '#f8fafc', stroke: '#64748b', text: '#334155', badge: 'bg-slate-100 text-slate-700 border-slate-200' };
  };

  return (
    <div className="bg-white border border-slate-200 rounded-3xl shadow-xs overflow-hidden flex flex-col transition-all">
      {/* Header & Controls Toolbar */}
      <div className="px-6 py-4 bg-slate-50/80 border-b border-slate-200/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-2xl bg-indigo-50 border border-indigo-200/80 flex items-center justify-center text-indigo-600 shadow-2xs">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-900 tracking-tight">Interactive Entity Relationship Graph</h3>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-indigo-100/70 text-indigo-800 border border-indigo-200/60 font-mono">
                {graphData.stats.total_nodes} nodes · {graphData.stats.total_edges} edges
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Interactive topological mapping of root files, IOCs, threat intel, email hops, network targets, and TTPs. Grab nodes to rearrange.
            </p>
          </div>
        </div>

        {/* Viewport Zoom / Pan Controls & Drag Hint */}
        <div className="flex items-center gap-2">
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-slate-100/80 text-[11px] font-medium text-slate-500 border border-slate-200/60">
            <Move className="w-3.5 h-3.5 text-slate-400" />
            <span>Drag nodes to position</span>
          </div>

          <div className="flex items-center gap-1 bg-white border border-slate-200 rounded-xl p-1 shadow-2xs">
            <button
              onClick={() => setZoom(prev => Math.min(2.5, prev + 0.2))}
              title="Zoom In"
              className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              onClick={() => setZoom(prev => Math.max(0.4, prev - 0.2))}
              title="Zoom Out"
              className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={handleResetView}
              title="Reset View"
              className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Quick Filter Bar */}
      <div className="px-6 py-2.5 bg-slate-50/50 border-b border-slate-200/60 flex items-center gap-1.5 overflow-x-auto text-xs font-medium scrollbar-thin">
        <button
          onClick={() => setActiveFilter('all')}
          className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
            activeFilter === 'all'
              ? 'bg-slate-900 text-white shadow-2xs font-semibold'
              : 'text-slate-600 hover:bg-slate-200/60 hover:text-slate-900'
          }`}
        >
          All Entities ({graphData.stats.total_nodes})
        </button>

        {graphData.stats.threat_intel_count > 0 && (
          <button
            onClick={() => setActiveFilter('intel')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'intel'
                ? 'bg-rose-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-rose-50 hover:text-rose-700'
            }`}
          >
            Threat Intel ({graphData.stats.threat_intel_count})
          </button>
        )}

        {graphData.stats.email_artifacts_count > 0 && (
          <button
            onClick={() => setActiveFilter('email')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'email'
                ? 'bg-blue-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-blue-50 hover:text-blue-700'
            }`}
          >
            Email & Identity ({graphData.stats.email_artifacts_count})
          </button>
        )}

        {graphData.stats.url_count > 0 && (
          <button
            onClick={() => setActiveFilter('network')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'network'
                ? 'bg-teal-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-teal-50 hover:text-teal-700'
            }`}
          >
            Network & Geo ({graphData.stats.url_count})
          </button>
        )}

        {graphData.stats.embedded_count > 0 && (
          <button
            onClick={() => setActiveFilter('payloads')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'payloads'
                ? 'bg-amber-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-amber-50 hover:text-amber-700'
            }`}
          >
            Payloads & Hashes ({graphData.stats.embedded_count})
          </button>
        )}

        {graphData.stats.certificate_count > 0 && (
          <button
            onClick={() => setActiveFilter('trust')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'trust'
                ? 'bg-emerald-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-emerald-50 hover:text-emerald-700'
            }`}
          >
            Certificates ({graphData.stats.certificate_count})
          </button>
        )}

        {(graphData.stats.technique_count > 0 || graphData.stats.similar_count > 0) && (
          <button
            onClick={() => setActiveFilter('ttps')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'ttps'
                ? 'bg-purple-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-purple-50 hover:text-purple-700'
            }`}
          >
            TTPs & Clusters ({graphData.stats.technique_count + graphData.stats.similar_count})
          </button>
        )}

        {(graphData.stats.forensic_count || 0) > 0 && (
          <button
            onClick={() => setActiveFilter('forensics')}
            className={`px-3 py-1 rounded-xl transition-all cursor-pointer ${
              activeFilter === 'forensics'
                ? 'bg-indigo-600 text-white shadow-2xs font-semibold'
                : 'text-slate-600 hover:bg-indigo-50 hover:text-indigo-700'
            }`}
          >
            Forensics &amp; Cross-Log ({graphData.stats.forensic_count})
          </button>
        )}
      </div>

      {/* Main Canvas + Side Inspector Layout */}
      <div className="relative w-full h-[620px] bg-slate-50/70 overflow-hidden flex select-none">
        {/* SVG Visualization Canvas */}
        <svg
          ref={svgRef}
          id="graph-canvas-bg"
          className="w-full h-full cursor-grab active:cursor-grabbing"
          onMouseDown={handleSvgMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onClick={(e) => {
            if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).id === 'graph-canvas-bg') {
              setSelectedNode(null);
            }
          }}
        >
          <defs>
            {/* Edge Arrow Markers */}
            <marker
              id="arrowhead-slate"
              markerWidth="9"
              markerHeight="6"
              refX="17"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 9 3, 0 6" fill="#94a3b8" />
            </marker>
            <marker
              id="arrowhead-danger"
              markerWidth="9"
              markerHeight="6"
              refX="17"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 9 3, 0 6" fill="#f43f5e" />
            </marker>
            <marker
              id="arrowhead-indigo"
              markerWidth="9"
              markerHeight="6"
              refX="17"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 9 3, 0 6" fill="#6366f1" />
            </marker>

            {/* Subtle Dot Matrix Pattern */}
            <pattern id="light-dot-grid" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="2" cy="2" r="1.2" fill="#cbd5e1" opacity="0.65" />
            </pattern>
          </defs>

          {/* Dot Matrix Background */}
          <rect id="graph-canvas-bg" width="100%" height="100%" fill="url(#light-dot-grid)" />

          {/* Graph Content Group with Zoom/Pan */}
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            {filteredEdges.map((edge, idx) => {
              const srcPos = nodePositions[edge.source];
              const tgtPos = nodePositions[edge.target];
              if (!srcPos || !tgtPos) return null;

              const isDanger = edge.type === 'contains' || edge.type === 'signature_match' || edge.type === 'similar_to';
              const isDirect = edge.source === 'root' || edge.target === 'root';
              const midX = (srcPos.x + tgtPos.x) / 2;
              const midY = (srcPos.y + tgtPos.y) / 2;

              let markerUrl = 'url(#arrowhead-slate)';
              let strokeColor = '#94a3b8';
              let strokeWidth = 1.2;

              if (isDanger) {
                markerUrl = 'url(#arrowhead-danger)';
                strokeColor = '#f43f5e';
                strokeWidth = 1.8;
              } else if (isDirect) {
                markerUrl = 'url(#arrowhead-indigo)';
                strokeColor = '#818cf8';
                strokeWidth = 1.4;
              }

              return (
                <g key={`edge-${idx}`}>
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={edge.type === 'similar_to' ? '4 3' : 'none'}
                    markerEnd={markerUrl}
                    opacity="0.8"
                  />
                  {edge.label && (
                    <g transform={`translate(${midX}, ${midY})`}>
                      <rect
                        x="-38"
                        y="-8"
                        width="76"
                        height="16"
                        rx="4"
                        fill="#ffffff"
                        stroke="#e2e8f0"
                        strokeWidth="0.8"
                        opacity="0.95"
                      />
                      <text
                        y="3"
                        fill="#64748b"
                        fontSize="8.5"
                        fontWeight="600"
                        fontFamily="ui-sans-serif, system-ui, sans-serif"
                        textAnchor="middle"
                        className="pointer-events-none select-none"
                      >
                        {edge.label.length > 14 ? edge.label.substring(0, 13) + '..' : edge.label}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {filteredNodes.map(node => {
              const pos = nodePositions[node.id];
              if (!pos) return null;

              const styling = getNodeStyling(node);
              const isSelected = selectedNode?.id === node.id;
              const isHovered = hoveredNodeId === node.id;
              const isRoot = node.id === 'root';
              const radius = isRoot ? 26 : 20;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onMouseDown={(e) => handleNodeMouseDown(node, e)}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (!hasDraggedNodeRef.current) {
                      setSelectedNode(prev => prev?.id === node.id ? null : node);
                    }
                  }}
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  className="cursor-pointer"
                >
                  {/* Selected / Hover Halo (Pure SVG, NO transform scales = NO jumping!) */}
                  {(isSelected || isHovered) && (
                    <circle
                      r={radius + 6}
                      fill="none"
                      stroke={isSelected ? '#6366f1' : styling.stroke}
                      strokeWidth={isSelected ? 2.5 : 1.5}
                      strokeDasharray={isSelected ? '4 3' : 'none'}
                      opacity={isSelected ? '0.9' : '0.6'}
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r={radius}
                    fill={styling.fill}
                    stroke={styling.stroke}
                    strokeWidth={isRoot ? 3 : (isHovered ? 2.5 : 1.8)}
                    className="filter drop-shadow-xs transition-colors"
                  />

                  {/* Node Center Label / Type Indicator */}
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={styling.text}
                    fontWeight="700"
                    fontSize={isRoot ? '11' : '9.5'}
                    fontFamily="ui-monospace, monospace"
                    className="pointer-events-none select-none"
                  >
                    {isRoot
                      ? 'FILE'
                      : node.type === 'threat_intel'
                      ? 'INTEL'
                      : node.type === 'threat_signature'
                      ? 'SIG'
                      : node.type === 'user'
                      ? 'USER'
                      : node.type === 'auth_policy'
                      ? 'AUTH'
                      : node.type === 'tracking_pixel'
                      ? 'PIXEL'
                      : node.type === 'domain'
                      ? 'DOM'
                      : node.type === 'ip'
                      ? 'IP'
                      : node.type === 'geolocation'
                      ? 'GEO'
                      : node.type === 'certificate'
                      ? 'CERT'
                      : node.type === 'embedded_file'
                      ? 'PAYL'
                      : node.type === 'technique'
                      ? 'TTP'
                      : node.type === 'similar_sample'
                      ? 'SIM'
                      : node.type === 'protocol'
                      ? 'PROTO'
                      : node.type === 'flow'
                      ? 'FLOW'
                      : node.type === 'log_source'
                      ? 'LOG'
                      : node.type === 'computer'
                      ? 'HOST'
                      : node.type === 'share'
                      ? 'SHAR'
                      : node.type === 'process'
                      ? 'PROC'
                      : node.type.substring(0, 4).toUpperCase()}
                  </text>

                  {/* Node Label Below */}
                  <g transform={`translate(0, ${radius + 14})`}>
                    <rect
                      x={-(Math.min(node.label.length * 3.4 + 10, 80))}
                      y="-7"
                      width={Math.min(node.label.length * 6.8 + 20, 160)}
                      height="17"
                      rx="8"
                      fill="#ffffff"
                      stroke="#e2e8f0"
                      strokeWidth="0.8"
                      className="filter drop-shadow-2xs"
                    />
                    <text
                      y="4"
                      textAnchor="middle"
                      fill="#1e293b"
                      fontSize="9"
                      fontWeight="600"
                      fontFamily="ui-sans-serif, system-ui, sans-serif"
                      className="pointer-events-none select-none"
                    >
                      {node.label}
                    </text>
                  </g>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Floating Detail Inspector Drawer (Light theme) */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-84 bg-white/95 backdrop-blur-md border border-slate-200/90 rounded-3xl p-5 shadow-2xl z-20 animate-in fade-in slide-in-from-right duration-200">
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-100">
              <div>
                <span className={`text-[10px] uppercase font-bold tracking-wider px-2.5 py-0.5 rounded-full border ${getNodeStyling(selectedNode).badge}`}>
                  {selectedNode.type.replace('_', ' ')}
                </span>
                <h4 className="font-bold text-sm text-slate-900 mt-2 break-all leading-snug">
                  {selectedNode.full_label || selectedNode.label}
                </h4>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-700 p-1.5 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
                title="Close Details"
              >
                ✕
              </button>
            </div>

            {/* Key-Value Details */}
            <div className="py-3.5 space-y-2.5 text-xs">
              <div className="flex items-center justify-between text-slate-500 py-0.5">
                <span className="font-medium">Threat Risk Level</span>
                <span className={`capitalize font-bold px-2 py-0.5 rounded-lg border text-[11px] ${
                  selectedNode.risk === 'critical' || selectedNode.risk === 'malicious'
                    ? 'bg-rose-50 text-rose-700 border-rose-200'
                    : selectedNode.risk === 'high'
                    ? 'bg-orange-50 text-orange-700 border-orange-200'
                    : selectedNode.risk === 'warning' || selectedNode.risk === 'medium'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}>
                  {selectedNode.risk}
                </span>
              </div>

              {Boolean(selectedNode.details?.is_cross_log_pivot) && (
                <div className="p-2.5 bg-indigo-50 border border-indigo-200 rounded-xl text-indigo-900 text-xs font-medium space-y-1">
                  <div className="font-bold flex items-center gap-1.5 text-indigo-800">
                    <span>🔗 Cross-Log Correlated Pivot</span>
                  </div>
                  <p className="text-[11px] text-indigo-700">
                    Observed across {selectedNode.details?.observed_in_files?.length || 2} separate EVTX logs, indicating shared identity or lateral movement.
                  </p>
                </div>
              )}

              {/* Dynamic Metadata Attributes */}
              {selectedNode.details &&
                Object.entries(selectedNode.details).map(([k, v]) => {
                  if (v === null || v === undefined || v === '') return null;
                  if (typeof v === 'object' && !Array.isArray(v)) return null;
                  const strVal = Array.isArray(v) ? v.join(', ') : String(v);
                  const isHashOrIp = k.toLowerCase().includes('hash') || k === 'sha256' || k === 'ip' || k === 'ip_address';

                  return (
                    <div key={k} className="flex flex-col gap-0.5 pt-1 border-t border-slate-100">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-semibold text-slate-500 capitalize">
                          {k.replace(/_/g, ' ')}
                        </span>
                        {isHashOrIp && (
                          <button
                            onClick={() => copyToClipboard(strVal, k)}
                            className="text-[10px] text-indigo-600 hover:text-indigo-800 flex items-center gap-1 cursor-pointer"
                          >
                            {copiedKey === k ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === k ? 'Copied' : 'Copy'}</span>
                          </button>
                        )}
                      </div>
                      <span className="text-slate-800 font-mono text-[11px] break-all bg-slate-50 p-1.5 rounded-lg border border-slate-100">
                        {strVal}
                      </span>
                    </div>
                  );
                })}
            </div>

            {/* Quick Actions Footer */}
            <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
              {selectedNode.type === 'similar_sample' && selectedNode.details?.job_id && onSelectJob && (
                <button
                  onClick={() => onSelectJob(selectedNode.details!.job_id)}
                  className="w-full py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 cursor-pointer shadow-xs"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Inspect Sample</span>
                </button>
              )}

              {selectedNode.type === 'threat_intel' && selectedNode.details?.permalink && (
                <a
                  href={selectedNode.details.permalink}
                  target="_blank"
                  rel="noreferrer"
                  className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 text-center cursor-pointer shadow-xs"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>Open Threat Intel Portal</span>
                </a>
              )}

              {selectedNode.type === 'technique' && selectedNode.details?.url && (
                <a
                  href={selectedNode.details.url}
                  target="_blank"
                  rel="noreferrer"
                  className="w-full py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 text-center cursor-pointer shadow-xs"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  <span>MITRE ATT&CK Matrix ↗</span>
                </a>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
