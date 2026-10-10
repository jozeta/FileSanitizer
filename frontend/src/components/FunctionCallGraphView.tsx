import React, { useState, useMemo, useRef, useEffect } from 'react';
import {
  GitFork,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  Layers,
  Maximize2,
  PanelRightClose,
  PanelRightOpen,
  X
} from 'lucide-react';
import { CallGraphData, CallGraphNode } from '../types';

interface FunctionCallGraphViewProps {
  callGraphData: CallGraphData;
  onOpenXrefs?: (symbol: string) => void;
  onJumpToAddress?: (address: string) => void;
}

interface CallGraphMinimapProps {
  nodes: CallGraphNode[];
  nodePositions: Map<string, { x: number; y: number }>;
  layoutWidth: number;
  layoutHeight: number;
  panOffset: { x: number; y: number };
  zoomLevel: number;
  containerWidth: number;
  containerHeight: number;
  selectedNodeId: string | null;
  onNavigate: (newPanX: number, newPanY: number) => void;
}

const CallGraphMinimap: React.FC<CallGraphMinimapProps> = ({
  nodes,
  nodePositions,
  layoutWidth,
  layoutHeight,
  panOffset,
  zoomLevel,
  containerWidth,
  containerHeight,
  selectedNodeId,
  onNavigate
}) => {
  const mapW = 160;
  const mapH = 110;
  const scale = Math.min(mapW / Math.max(layoutWidth, 1), mapH / Math.max(layoutHeight, 1));

  const worldVx = -panOffset.x / zoomLevel;
  const worldVy = -panOffset.y / zoomLevel;
  const worldVw = containerWidth / zoomLevel;
  const worldVh = containerHeight / zoomLevel;

  const vx = Math.max(0, Math.min(mapW - 10, worldVx * scale));
  const vy = Math.max(0, Math.min(mapH - 10, worldVy * scale));
  const vw = Math.min(mapW - vx, Math.max(10, worldVw * scale));
  const vh = Math.min(mapH - vy, Math.max(10, worldVh * scale));

  const handleClick = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;
    const targetWorldX = clickX / scale;
    const targetWorldY = clickY / scale;
    const newPanX = -(targetWorldX * zoomLevel - containerWidth / 2);
    const newPanY = -(targetWorldY * zoomLevel - containerHeight / 2);
    onNavigate(newPanX, newPanY);
  };

  return (
    <div className="absolute right-3 bottom-3 z-20 bg-white/95 backdrop-blur-xs border border-slate-300 rounded-lg shadow-md p-1.5 pointer-events-auto select-none">
      <div className="text-[9px] font-mono font-bold text-slate-500 px-1 pb-1 border-b border-slate-100 flex items-center justify-between">
        <span>CALL GRAPH MAP</span>
        <span className="text-[8px] text-slate-400 font-semibold">{Math.round(zoomLevel * 100)}%</span>
      </div>
      <svg
        width={mapW}
        height={mapH}
        className="cursor-crosshair mt-1 bg-slate-50 rounded border border-slate-200"
        onClick={handleClick}
      >
        {nodes.map((node) => {
          const pos = nodePositions.get(node.id);
          if (!pos) return null;
          const isSelected = node.id === selectedNodeId;
          const nx = (pos.x - 90) * scale;
          const ny = (pos.y - 20) * scale;
          const nw = Math.max(6, 180 * scale);
          const nh = Math.max(4, 42 * scale);
          const fill = node.is_root
            ? '#6366f1'
            : node.risk === 'critical'
            ? '#f43f5e'
            : node.risk === 'high'
            ? '#f59e0b'
            : node.node_type === 'RESOLVED_HASH'
            ? '#a855f7'
            : node.node_type === 'EXPORT'
            ? '#10b981'
            : '#94a3b8';

          return (
            <rect
              key={node.id}
              x={nx}
              y={ny}
              width={nw}
              height={nh}
              rx={1.5}
              fill={fill}
              stroke={isSelected ? '#2563eb' : '#cbd5e1'}
              strokeWidth={isSelected ? 1.5 : 0.5}
            />
          );
        })}
        {/* Viewport Box */}
        <rect
          x={vx}
          y={vy}
          width={vw}
          height={vh}
          fill="rgba(59, 130, 246, 0.12)"
          stroke="#2563eb"
          strokeWidth={1.5}
          strokeDasharray="2 2"
          pointerEvents="none"
        />
      </svg>
    </div>
  );
};

export const FunctionCallGraphView: React.FC<FunctionCallGraphViewProps> = ({
  callGraphData,
  onOpenXrefs,
  onJumpToAddress
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [focusMode, setFocusMode] = useState<'all' | 'focused'>('all');
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(true);
  const [containerDimensions, setContainerDimensions] = useState<{ width: number; height: number }>({
    width: 900,
    height: 600
  });

  const containerRef = useRef<HTMLDivElement>(null);

  // Monitor container resize for accurate centering and fitToView
  useEffect(() => {
    if (!containerRef.current) return;
    const updateDimensions = () => {
      if (containerRef.current) {
        setContainerDimensions({
          width: containerRef.current.clientWidth || 900,
          height: containerRef.current.clientHeight || 600
        });
      }
    };
    updateDimensions();
    const observer = new ResizeObserver(updateDimensions);
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Set default selected node to root entry point if available
  useEffect(() => {
    if (!selectedNodeId && callGraphData.nodes.length > 0) {
      const root = callGraphData.nodes.find((n) => n.is_root) || callGraphData.nodes[0];
      setSelectedNodeId(root.id);
    }
  }, [callGraphData, selectedNodeId]);

  // Layout calculation for nodes
  const layout = useMemo(() => {
    const nodes = callGraphData.nodes;
    const edges = callGraphData.edges;

    if (!nodes || nodes.length === 0) {
      return { nodePositions: new Map<string, { x: number; y: number }>(), width: 900, height: 600 };
    }

    // Partition into levels via topological or BFS depth from roots
    const rootNodes = nodes.filter((n) => n.is_root || n.in_degree === 0);
    const effectiveRoots = rootNodes.length > 0 ? rootNodes : [nodes[0]];

    const levels: Map<string, number> = new Map();
    const visited = new Set<string>();
    const queue: Array<{ id: string; depth: number }> = effectiveRoots.map((r) => ({ id: r.id, depth: 0 }));

    while (queue.length > 0) {
      const { id, depth } = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      levels.set(id, depth);

      // Find children
      const childEdges = edges.filter((e) => e.source === id);
      childEdges.forEach((e) => {
        if (!visited.has(e.target)) {
          queue.push({ id: e.target, depth: depth + 1 });
        }
      });
    }

    // Assign any unvisited nodes to level 1 or 2
    nodes.forEach((n) => {
      if (!levels.has(n.id)) {
        levels.set(n.id, 1);
      }
    });

    // Group nodes by depth level
    const depthGroups: Map<number, string[]> = new Map();
    levels.forEach((lvl, id) => {
      if (!depthGroups.has(lvl)) depthGroups.set(lvl, []);
      depthGroups.get(lvl)!.push(id);
    });

    const nodePositions = new Map<string, { x: number; y: number }>();
    const levelHeight = 160;
    const nodeWidth = 220;

    // Pass 1: compute maximum width required across all depth tiers
    let maxW = 900;
    depthGroups.forEach((nodeIds) => {
      const count = nodeIds.length;
      const totalWidth = count * (nodeWidth + 60);
      maxW = Math.max(maxW, totalWidth + 160);
    });

    // Pass 2: place nodes centered horizontally within maxW
    depthGroups.forEach((nodeIds, lvl) => {
      const count = nodeIds.length;
      const totalWidth = count * (nodeWidth + 60);
      const startX = Math.max(80, (maxW - totalWidth) / 2);
      nodeIds.forEach((id, idx) => {
        const x = startX + idx * (nodeWidth + 60) + nodeWidth / 2;
        const y = 80 + lvl * levelHeight;
        nodePositions.set(id, { x, y });
      });
    });

    const maxH = Math.max(600, (depthGroups.size + 1) * levelHeight + 100);

    return { nodePositions, width: maxW, height: maxH };
  }, [callGraphData]);

  // Selected node caller and callee sets for path highlighting
  const { callersSet, calleesSet } = useMemo(() => {
    const callers = new Set<string>();
    const callees = new Set<string>();

    if (selectedNodeId) {
      callGraphData.edges.forEach((e) => {
        if (e.target === selectedNodeId) callers.add(e.source);
        if (e.source === selectedNodeId) callees.add(e.target);
      });
    }

    return { callersSet: callers, calleesSet: callees };
  }, [callGraphData, selectedNodeId]);

  // Selected node metadata
  const selectedNode = useMemo(() => {
    return callGraphData.nodes.find((n) => n.id === selectedNodeId);
  }, [callGraphData, selectedNodeId]);

  // Filtered nodes based on search or focus mode
  const visibleNodes = useMemo(() => {
    return callGraphData.nodes.filter((node) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          node.label.toLowerCase().includes(q) ||
          node.address.toLowerCase().includes(q) ||
          node.node_type.toLowerCase().includes(q)
        );
      }
      if (focusMode === 'focused' && selectedNodeId) {
        return (
          node.id === selectedNodeId ||
          callersSet.has(node.id) ||
          calleesSet.has(node.id)
        );
      }
      return true;
    });
  }, [callGraphData, searchQuery, focusMode, selectedNodeId, callersSet, calleesSet]);

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);

  const visibleEdges = useMemo(() => {
    return callGraphData.edges.filter(
      (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
    );
  }, [callGraphData, visibleNodeIds]);

  // Pan and drag handlers with global window listeners
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
    }
  };

  useEffect(() => {
    if (!isDragging) return;

    const handleWindowMouseMove = (e: MouseEvent) => {
      setPanOffset({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    };

    const handleWindowMouseUp = () => {
      setIsDragging(false);
    };

    window.addEventListener('mousemove', handleWindowMouseMove);
    window.addEventListener('mouseup', handleWindowMouseUp);

    return () => {
      window.removeEventListener('mousemove', handleWindowMouseMove);
      window.removeEventListener('mouseup', handleWindowMouseUp);
    };
  }, [isDragging, dragStart]);

  // Wheel zoom and pan handler
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) {
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      setZoomLevel((prev) => Math.min(2.5, Math.max(0.15, prev * zoomFactor)));
    } else {
      setPanOffset((prev) => ({
        x: prev.x - e.deltaX * 0.8,
        y: prev.y - e.deltaY * 0.8
      }));
    }
  };

  // Attach non-passive wheel listener for smooth zoom/pan across all browsers
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onNativeWheel = (e: WheelEvent) => {
      e.preventDefault();
      if (e.ctrlKey || e.metaKey) {
        const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
        setZoomLevel((prev) => Math.min(2.5, Math.max(0.15, prev * zoomFactor)));
      } else {
        setPanOffset((prev) => ({
          x: prev.x - e.deltaX * 0.8,
          y: prev.y - e.deltaY * 0.8
        }));
      }
    };
    el.addEventListener('wheel', onNativeWheel, { passive: false });
    return () => el.removeEventListener('wheel', onNativeWheel);
  }, []);

  // Fit and center graph inside container
  const fitToView = () => {
    const containerW = containerDimensions.width || (containerRef.current?.clientWidth || 800);
    const containerH = containerDimensions.height || (containerRef.current?.clientHeight || 500);
    const scaleX = (containerW - 80) / Math.max(layout.width, 1);
    const scaleY = (containerH - 80) / Math.max(layout.height, 1);
    const fitScale = Math.min(1.2, Math.max(0.15, Math.min(scaleX, scaleY)));
    setZoomLevel(fitScale);
    setPanOffset({
      x: (containerW - layout.width * fitScale) / 2,
      y: 40
    });
  };

  // Center on initial mount and when layout or container dimensions change
  useEffect(() => {
    fitToView();
  }, [layout, containerDimensions.width, containerDimensions.height]);

  const resetView = () => {
    fitToView();
    setSearchQuery('');
    setFocusMode('all');
  };

  const getNodeColor = (node: CallGraphNode) => {
    if (node.is_root) return { bg: 'fill-indigo-50', border: 'stroke-indigo-500', text: 'text-indigo-900', badge: 'bg-indigo-100 text-indigo-800' };
    if (node.node_type === 'RESOLVED_HASH') return { bg: 'fill-purple-50', border: 'stroke-purple-500', text: 'text-purple-900', badge: 'bg-purple-100 text-purple-800' };
    if (node.node_type === 'IMPORT_API') {
      if (node.risk === 'critical') return { bg: 'fill-rose-50', border: 'stroke-rose-500', text: 'text-rose-900', badge: 'bg-rose-100 text-rose-800' };
      if (node.risk === 'high') return { bg: 'fill-amber-50', border: 'stroke-amber-500', text: 'text-amber-900', badge: 'bg-amber-100 text-amber-800' };
      return { bg: 'fill-blue-50', border: 'stroke-blue-400', text: 'text-blue-900', badge: 'bg-blue-100 text-blue-800' };
    }
    if (node.node_type === 'EXPORT') return { bg: 'fill-emerald-50', border: 'stroke-emerald-500', text: 'text-emerald-900', badge: 'bg-emerald-100 text-emerald-800' };
    return { bg: 'fill-slate-50', border: 'stroke-slate-300', text: 'text-slate-900', badge: 'bg-slate-100 text-slate-700' };
  };

  return (
    <div className="flex flex-col h-full bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
      {/* Top Toolbar */}
      <div className="p-3 border-b border-slate-200 bg-slate-50/60 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-blue-100/70 text-blue-700 rounded-lg">
            <GitFork className="w-4 h-4" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-slate-900">Interactive Visual Call Hierarchy</h4>
            <p className="text-[11px] text-slate-500">
              Inter-procedural directed call graph with API hazard scoring and dynamic hash nodes.
            </p>
          </div>
        </div>

        {/* Search & Mode Controls */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search functions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500 w-44"
            />
          </div>

          <div className="flex items-center bg-white border border-slate-200 rounded-lg p-0.5 text-xs">
            <button
              onClick={() => setFocusMode('all')}
              className={`px-2 py-0.5 rounded font-medium transition-colors ${
                focusMode === 'all' ? 'bg-blue-50 text-blue-700 font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Full Graph ({callGraphData.nodes.length})
            </button>
            <button
              onClick={() => setFocusMode('focused')}
              disabled={!selectedNodeId}
              className={`px-2 py-0.5 rounded font-medium transition-colors disabled:opacity-40 ${
                focusMode === 'focused' ? 'bg-blue-50 text-blue-700 font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Focus Callers & Callees
            </button>
          </div>

          {/* Zoom and Pan Controls */}
          <div className="flex items-center bg-white border border-slate-200 rounded-lg p-0.5">
            <button
              onClick={() => setZoomLevel((z) => Math.min(2.5, Math.round((z + 0.15) * 100) / 100))}
              className="p-1 hover:bg-slate-100 rounded text-slate-600"
              title="Zoom in"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <span className="px-1.5 text-[11px] font-mono text-slate-500">
              {Math.round(zoomLevel * 100)}%
            </span>
            <button
              onClick={() => setZoomLevel((z) => Math.max(0.15, Math.round((z - 0.15) * 100) / 100))}
              className="p-1 hover:bg-slate-100 rounded text-slate-600"
              title="Zoom out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={fitToView}
              className="p-1 hover:bg-slate-100 rounded text-slate-600 ml-0.5"
              title="Fit to view (center all nodes)"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={resetView}
              className="p-1 hover:bg-slate-100 rounded text-slate-600 ml-0.5"
              title="Reset view"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Toggle Inspector Drawer */}
          <button
            onClick={() => setIsDrawerOpen((prev) => !prev)}
            className={`p-1.5 rounded-lg border text-xs font-medium flex items-center gap-1 transition-colors ${
              isDrawerOpen
                ? 'bg-blue-50 border-blue-200 text-blue-700'
                : 'bg-white border-slate-200 text-slate-600 hover:text-slate-900'
            }`}
            title={isDrawerOpen ? 'Collapse inspector drawer' : 'Expand inspector drawer'}
          >
            {isDrawerOpen ? <PanelRightClose className="w-3.5 h-3.5" /> : <PanelRightOpen className="w-3.5 h-3.5" />}
            <span className="text-[11px]">{isDrawerOpen ? 'Hide Details' : 'Show Details'}</span>
          </button>
        </div>
      </div>

      {/* Main Canvas + Inspector Split */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* SVG Graph Canvas */}
        <div
          ref={containerRef}
          onMouseDown={handleMouseDown}
          onWheel={handleWheel}
          className="flex-1 overflow-hidden bg-slate-50/40 cursor-grab active:cursor-grabbing relative select-none"
        >
          {/* Subtle Grid Background */}
          <svg className="w-full h-full absolute inset-0 pointer-events-none opacity-30">
            <defs>
              <pattern id="callgraph-grid" width="24" height="24" patternUnits="userSpaceOnUse">
                <circle cx="12" cy="12" r="0.75" fill="#94a3b8" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#callgraph-grid)" />
          </svg>

          {/* Graph Content SVG */}
          <svg
            className="w-full h-full"
            style={{ overflow: 'hidden' }}
          >
            <g
              transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}
              style={{
                transformOrigin: '0 0',
                transition: isDragging ? 'none' : 'transform 0.08s ease-out'
              }}
            >
            <defs>
              {/* Arrow markers */}
              <marker
                id="call-arrow"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#94a3b8" />
              </marker>
              <marker
                id="call-arrow-highlight-caller"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#2563eb" />
              </marker>
              <marker
                id="call-arrow-highlight-callee"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#059669" />
              </marker>
            </defs>

            {/* Render Edges */}
            {visibleEdges.map((edge) => {
              const srcPos = layout.nodePositions.get(edge.source);
              const tgtPos = layout.nodePositions.get(edge.target);
              if (!srcPos || !tgtPos) return null;

              const isCallerEdge = edge.target === selectedNodeId;
              const isCalleeEdge = edge.source === selectedNodeId;

              let stroke = '#cbd5e1';
              let strokeWidth = 1.5;
              let markerEnd = 'url(#call-arrow)';

              if (isCallerEdge) {
                stroke = '#2563eb';
                strokeWidth = 2.5;
                markerEnd = 'url(#call-arrow-highlight-caller)';
              } else if (isCalleeEdge) {
                stroke = '#059669';
                strokeWidth = 2.5;
                markerEnd = 'url(#call-arrow-highlight-callee)';
              }

              // Curved Bezier Path
              const midY = (srcPos.y + tgtPos.y) / 2;

              const pathData = `M ${srcPos.x} ${srcPos.y + 24} C ${srcPos.x} ${midY}, ${tgtPos.x} ${midY}, ${tgtPos.x} ${tgtPos.y - 24}`;

              return (
                <g key={edge.id}>
                  <path
                    d={pathData}
                    fill="none"
                    stroke={stroke}
                    strokeWidth={strokeWidth}
                    strokeDasharray={edge.call_type === 'DYNAMIC_RESOLVE' ? '4 3' : 'none'}
                    markerEnd={markerEnd}
                    className="transition-colors duration-150"
                  />
                  {edge.count > 1 && (
                    <text
                      x={(srcPos.x + tgtPos.x) / 2}
                      y={midY - 4}
                      fill="#64748b"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="select-none"
                    >
                      x{edge.count}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Render Nodes */}
            {visibleNodes.map((node) => {
              const pos = layout.nodePositions.get(node.id);
              if (!pos) return null;

              const isSelected = node.id === selectedNodeId;
              const isCaller = callersSet.has(node.id);
              const isCallee = calleesSet.has(node.id);
              const styling = getNodeColor(node);

              let ringClass = '';
              if (isSelected) ringClass = 'stroke-blue-600 stroke-[2.5] filter drop-shadow-md';
              else if (isCaller) ringClass = 'stroke-blue-400 stroke-2';
              else if (isCallee) ringClass = 'stroke-emerald-500 stroke-2';

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x - 90}, ${pos.y - 20})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNodeId(node.id);
                    setIsDrawerOpen(true);
                  }}
                  className="cursor-pointer group"
                >
                  {/* Node Box */}
                  <rect
                    width="180"
                    height="42"
                    rx="8"
                    className={`${styling.bg} ${styling.border} stroke-1 transition-all ${ringClass} group-hover:filter group-hover:drop-shadow-sm`}
                  />

                  {/* Left Accent Stripe */}
                  <path
                    d="M 0 8 Q 0 0 8 0 L 12 0 L 12 42 L 8 42 Q 0 42 0 34 Z"
                    className={
                      node.is_root
                        ? 'fill-indigo-500'
                        : node.risk === 'critical'
                        ? 'fill-rose-500'
                        : node.risk === 'high'
                        ? 'fill-amber-500'
                        : node.node_type === 'RESOLVED_HASH'
                        ? 'fill-purple-500'
                        : 'fill-blue-400'
                    }
                  />

                  {/* Label */}
                  <text
                    x="20"
                    y="18"
                    fontSize="11"
                    fontWeight="600"
                    fill="#0f172a"
                    className="font-mono select-none"
                  >
                    {node.label.length > 20 ? `${node.label.substring(0, 18)}…` : node.label}
                  </text>

                  {/* Address & Node Type Subtitle */}
                  <text
                    x="20"
                    y="32"
                    fontSize="9"
                    fill="#64748b"
                    className="font-mono select-none"
                  >
                    {node.address !== 'N/A' ? node.address : node.node_type} • {node.in_degree} in / {node.out_degree} out
                  </text>

                  {/* Risk Badge Icon */}
                  {node.risk === 'critical' && (
                    <circle cx="166" cy="14" r="5" fill="#f43f5e" />
                  )}
                  {node.risk === 'high' && (
                    <circle cx="166" cy="14" r="5" fill="#f59e0b" />
                  )}
                </g>
              );
            })}
            </g>
          </svg>

          {/* Minimap in lower-right corner */}
          <CallGraphMinimap
            nodes={callGraphData.nodes}
            nodePositions={layout.nodePositions}
            layoutWidth={layout.width}
            layoutHeight={layout.height}
            panOffset={panOffset}
            zoomLevel={zoomLevel}
            containerWidth={containerDimensions.width}
            containerHeight={containerDimensions.height}
            selectedNodeId={selectedNodeId}
            onNavigate={(newPanX, newPanY) => setPanOffset({ x: newPanX, y: newPanY })}
          />
        </div>

        {/* Selected Function Details Drawer */}
        {selectedNode && isDrawerOpen && (
          <div className="w-80 border-l border-slate-200 bg-white p-4 flex flex-col justify-between overflow-y-auto z-10 shadow-sm shrink-0">
            <div className="space-y-4">
              {/* Header */}
              <div className="border-b border-slate-100 pb-3">
                <div className="flex items-center justify-between mb-1">
                  <span className={`px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded border ${getNodeColor(selectedNode).badge}`}>
                    {selectedNode.node_type}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {selectedNode.risk !== 'info' && (
                      <span className="flex items-center gap-1 text-[11px] font-semibold text-rose-600 bg-rose-50 px-2 py-0.5 rounded border border-rose-200">
                        <ShieldAlert className="w-3 h-3" />
                        {selectedNode.risk.toUpperCase()}
                      </span>
                    )}
                    <button
                      onClick={() => setIsDrawerOpen(false)}
                      className="p-1 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded transition-colors"
                      title="Close drawer"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
                <h5 className="font-mono text-sm font-bold text-slate-900 break-all">
                  {selectedNode.label}
                </h5>
                <p className="text-xs font-mono text-slate-500 mt-0.5">
                  Virtual Address: {selectedNode.address}
                </p>
              </div>

              {/* Suspicious Constructs / Flags */}
              {selectedNode.suspicious_flags.length > 0 && (
                <div className="bg-rose-50/70 border border-rose-200 rounded-lg p-2.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-800 mb-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                    Security Assessment Flags
                  </div>
                  <ul className="text-xs text-rose-700 space-y-1 pl-4 list-disc">
                    {selectedNode.suspicious_flags.map((flag, i) => (
                      <li key={i}>{flag}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Call Statistics */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Callers (In)</span>
                  <span className="text-base font-bold text-blue-700 font-mono">{selectedNode.in_degree}</span>
                </div>
                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block">Callees (Out)</span>
                  <span className="text-base font-bold text-emerald-700 font-mono">{selectedNode.out_degree}</span>
                </div>
              </div>

              {/* Upstream Callers List */}
              <div>
                <h6 className="text-[11px] font-semibold text-slate-700 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Immediate Callers ({callersSet.size})
                </h6>
                {callersSet.size === 0 ? (
                  <p className="text-xs text-slate-400 italic">No incoming callers (Root or Entry routine)</p>
                ) : (
                  <div className="space-y-1 max-h-28 overflow-y-auto">
                    {Array.from(callersSet).map((callerId) => {
                      const cNode = callGraphData.nodes.find((n) => n.id === callerId);
                      return (
                        <button
                          key={callerId}
                          onClick={() => setSelectedNodeId(callerId)}
                          className="w-full text-left p-1.5 bg-slate-50 hover:bg-blue-50 text-slate-700 hover:text-blue-700 rounded font-mono text-xs truncate transition-colors border border-slate-200/60"
                        >
                          {cNode?.label || callerId}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Downstream Callees List */}
              <div>
                <h6 className="text-[11px] font-semibold text-slate-700 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                  Functions Called ({calleesSet.size})
                </h6>
                {calleesSet.size === 0 ? (
                  <p className="text-xs text-slate-400 italic">Leaf procedure (no external calls)</p>
                ) : (
                  <div className="space-y-1 max-h-28 overflow-y-auto">
                    {Array.from(calleesSet).map((calleeId) => {
                      const cNode = callGraphData.nodes.find((n) => n.id === calleeId);
                      return (
                        <button
                          key={calleeId}
                          onClick={() => setSelectedNodeId(calleeId)}
                          className="w-full text-left p-1.5 bg-slate-50 hover:bg-emerald-50 text-slate-700 hover:text-emerald-700 rounded font-mono text-xs truncate transition-colors border border-slate-200/60"
                        >
                          {cNode?.label || calleeId}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="pt-3 border-t border-slate-200 space-y-2">
              {onOpenXrefs && (
                <button
                  onClick={() => onOpenXrefs(selectedNode.label)}
                  className="w-full py-1.5 px-3 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Layers className="w-3.5 h-3.5" />
                  View All XREFs
                </button>
              )}
              {onJumpToAddress && selectedNode.address !== 'N/A' && (
                <button
                  onClick={() => onJumpToAddress(selectedNode.address)}
                  className="w-full py-1.5 px-3 bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  Jump to Disassembly Site
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer Legend */}
      <div className="p-2 border-t border-slate-200 bg-slate-50 text-[11px] text-slate-500 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-indigo-500 inline-block"></span>
            Entry Point
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-blue-400 inline-block"></span>
            Internal Subroutine
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-emerald-500 inline-block"></span>
            Exported Symbol
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-amber-500 inline-block"></span>
            Win32 / POSIX API
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-purple-500 inline-block"></span>
            Dynamically Resolved Hash
          </span>
        </div>
        <div>
          <span>
            {callGraphData.metrics.total_functions} procedures • {callGraphData.metrics.total_calls} calls •{' '}
            {callGraphData.metrics.high_risk_nodes_count} high-risk APIs
          </span>
        </div>
      </div>
    </div>
  );
};
