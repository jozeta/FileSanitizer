import React, { useState, useMemo, useRef, useEffect, useLayoutEffect } from 'react';
import {
  Network,
  Search,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Maximize2,
  Lock,
  Unlock,
  GripHorizontal,
  Repeat,
  Split,
  Layers,
  ExternalLink,
  X,
  ArrowRight,
  ArrowLeft
} from 'lucide-react';
import { BasicBlock, CFGEdge } from '../types';
import { useSymbolRenames } from '../context/SymbolRenameContext';

interface SingleBinaryFlowCanvasProps {
  blocks: BasicBlock[];
  edges: CFGEdge[];
  binaryName?: string;
  onOpenXrefs?: (symbol: string) => void;
  onJumpToAddress?: (address: string) => void;
}

interface LayoutNode {
  block: BasicBlock;
  x: number;
  y: number;
  width: number;
  height: number;
}

function computeExactBlockHeight(b: BasicBlock, expandedBlocks: Set<string>): number {
  const isExpanded = expandedBlocks.has(b.id);
  const totalInsts = b.instructions?.length || 0;
  const instCount = isExpanded ? totalInsts : Math.min(totalInsts, 5);
  const hasBadge = Boolean(b.is_loop_target || b.has_loop_exit || b.is_conditional);
  const hasMore = !isExpanded && totalInsts > 5;
  // Header: 29px, Badges: 22px, Instructions: 20px each, More note: 20px, Border/Padding: 4px
  return 29 + (hasBadge ? 22 : 0) + instCount * 20 + (hasMore ? 20 : 0) + 4;
}

function computeGraphCoordinates(
  blocks: BasicBlock[],
  edges: CFGEdge[],
  expandedBlocks: Set<string>,
  startX: number = 420
): {
  nodes: LayoutNode[];
  edges: CFGEdge[];
  canvasWidth: number;
  canvasHeight: number;
} {
  const NODE_WIDTH = 280;
  const H_GAP = 70;
  const V_GAP = 70;

  if (!blocks || blocks.length === 0) {
    return { nodes: [], edges: [], canvasWidth: 1000, canvasHeight: 750 };
  }

  // Pre-calculate heights based on instruction count & badges
  const blockHeights: Record<string, number> = {};
  blocks.forEach((b) => {
    blockHeights[b.id] = computeExactBlockHeight(b, expandedBlocks);
  });

  // Build adjacency list for forward edges (ignoring back-loops for DAG tiering)
  const adj: Record<string, Array<{ target: string; type: string }>> = {};
  blocks.forEach((b) => {
    adj[b.id] = [];
  });

  const forwardEdges = edges.filter((e) => {
    if (e.is_loop || e.type === 'loop') return false;
    const srcIdx = blocks.findIndex((b) => b.id === e.source);
    const tgtIdx = blocks.findIndex((b) => b.id === e.target);
    if (tgtIdx <= srcIdx && tgtIdx !== -1) return false;
    return true;
  });

  forwardEdges.forEach((e) => {
    if (adj[e.source]) {
      adj[e.source].push({ target: e.target, type: e.type });
    }
  });

  // Calculate ranks (levels) using longest-path / topological assignment
  const ranks: Record<string, number> = {};
  ranks[blocks[0].id] = 0;

  const queue: string[] = [blocks[0].id];
  const visited = new Set<string>([blocks[0].id]);

  while (queue.length > 0) {
    const currId = queue.shift()!;
    const currRank = ranks[currId] || 0;
    const children = adj[currId] || [];

    children.forEach((child) => {
      const existingRank = ranks[child.target];
      if (existingRank === undefined || existingRank < currRank + 1) {
        ranks[child.target] = currRank + 1;
      }
      if (!visited.has(child.target)) {
        visited.add(child.target);
        queue.push(child.target);
      }
    });
  }

  // Ensure every block has a rank
  blocks.forEach((b, idx) => {
    if (ranks[b.id] === undefined) {
      ranks[b.id] = idx;
    }
  });

  // Group blocks by rank
  const rankGroups: Record<number, BasicBlock[]> = {};
  blocks.forEach((b) => {
    const r = ranks[b.id];
    if (!rankGroups[r]) rankGroups[r] = [];
    rankGroups[r].push(b);
  });

  const sortedRanks = Object.keys(rankGroups)
    .map(Number)
    .sort((a, b) => a - b);

  // Calculate Y positions for each rank based on max height of previous ranks
  const rankY: Record<number, number> = {};
  let currentY = 50;
  sortedRanks.forEach((r) => {
    rankY[r] = currentY;
    const maxHeightInRank = Math.max(...rankGroups[r].map((b) => blockHeights[b.id] || 100));
    currentY += maxHeightInRank + V_GAP;
  });

  // Compute initial X positions
  const positions: Record<string, { x: number; y: number; width: number; height: number }> = {};

  sortedRanks.forEach((r) => {
    const blocksInRank = rankGroups[r];
    const totalWidth = blocksInRank.length * NODE_WIDTH + (blocksInRank.length - 1) * H_GAP;
    let baseLeft = startX - totalWidth / 2 + NODE_WIDTH / 2;

    blocksInRank.forEach((b, idx) => {
      const incoming = forwardEdges.filter((e) => e.target === b.id);
      let targetX = baseLeft + idx * (NODE_WIDTH + H_GAP);

      if (incoming.length === 1) {
        const parentPos = positions[incoming[0].source];
        if (parentPos) {
          if (incoming[0].type === 'true') {
            targetX = parentPos.x - (NODE_WIDTH / 2 + H_GAP / 2);
          } else if (incoming[0].type === 'false') {
            targetX = parentPos.x + (NODE_WIDTH / 2 + H_GAP / 2);
          } else if (blocksInRank.length === 1) {
            targetX = parentPos.x;
          }
        }
      }

      positions[b.id] = {
        x: targetX,
        y: rankY[r],
        width: NODE_WIDTH,
        height: blockHeights[b.id] || 100,
      };
    });

    // Sideways collision avoidance within the tier: ensure sorted by X and separated by H_GAP
    blocksInRank.sort((a, b) => positions[a.id].x - positions[b.id].x);
    for (let i = 1; i < blocksInRank.length; i++) {
      const prev = positions[blocksInRank[i - 1].id];
      const curr = positions[blocksInRank[i].id];
      const minX = prev.x + prev.width + H_GAP;
      if (curr.x < minX) {
        curr.x = minX;
      }
    }
  });

  // Global cross-tier collision resolution:
  // If any two blocks overlap in both X and Y dimensions, shift the one on the right sideways
  const allBlocks = [...blocks];
  for (let iter = 0; iter < 5; iter++) {
    let shifted = false;
    for (let i = 0; i < allBlocks.length; i++) {
      for (let j = i + 1; j < allBlocks.length; j++) {
        const b1 = positions[allBlocks[i].id];
        const b2 = positions[allBlocks[j].id];
        if (!b1 || !b2) continue;

        // Check vertical overlap
        const yOverlap = Math.min(b1.y + b1.height, b2.y + b2.height) - Math.max(b1.y, b2.y);
        // Check horizontal overlap with H_GAP buffer
        const xOverlap = Math.min(b1.x + b1.width, b2.x + b2.width) - Math.max(b1.x, b2.x);

        if (yOverlap > 0 && xOverlap > -H_GAP) {
          if (b2.x >= b1.x) {
            b2.x = b1.x + b1.width + H_GAP;
          } else {
            b1.x = b2.x + b2.width + H_GAP;
          }
          shifted = true;
        }
      }
    }
    if (!shifted) break;
  }

  // Ensure minimum left margin (at least 60px)
  const minX = Math.min(...Object.values(positions).map((p) => p.x));
  if (minX < 60) {
    const shiftRight = 60 - minX;
    Object.values(positions).forEach((p) => {
      p.x += shiftRight;
    });
  }

  const nodes: LayoutNode[] = blocks.map((b) => ({
    block: b,
    ...(positions[b.id] || { x: startX, y: 50, width: NODE_WIDTH, height: 100 }),
  }));

  const maxX = Math.max(...nodes.map((n) => n.x + n.width), 1000) + 160;
  const canvasH = Math.max(...nodes.map((n) => n.y + n.height), 750) + 160;

  return { nodes, edges, canvasWidth: Math.max(maxX, 1200), canvasHeight: Math.max(canvasH, 850) };
}

interface EdgePathResult {
  pathD: string;
  labelX: number;
  labelY: number;
  isLoop: boolean;
}

function computeEdgePathAndLabel(
  src: { id: string; x: number; y: number; width: number; height: number },
  tgt: { id: string; x: number; y: number; width: number; height: number },
  edge: CFGEdge,
  allNodes: Array<{ id: string; x: number; y: number; width: number; height: number }>,
  measuredHeights: Record<string, number> = {}
): EdgePathResult {
  const actualSrcH = measuredHeights[src.id] || src.height;
  const actualTgtH = measuredHeights[tgt.id] || tgt.height;

  const isExplicitLoop = edge.is_loop || edge.type === 'loop';

  // Spatial boundaries
  const srcBottom = src.y + actualSrcH;
  const srcTop = src.y;
  const srcRight = src.x + src.width;
  const srcLeft = src.x;

  const tgtBottom = tgt.y + actualTgtH;
  const tgtTop = tgt.y;
  const tgtRight = tgt.x + tgt.width;
  const tgtLeft = tgt.x;

  // 1. Explicit CFG Loop or back-edge when target is significantly higher than source
  if (isExplicitLoop) {
    const nodesBetween = allNodes.filter(
      (n) =>
        n.id !== src.id &&
        n.id !== tgt.id &&
        n.y <= Math.max(srcBottom, tgtBottom) &&
        n.y + (measuredHeights[n.id] || n.height) >= Math.min(srcTop, tgtTop)
    );
    const minX = Math.min(src.x, tgt.x, ...nodesBetween.map((n) => n.x));
    const gutterX = Math.max(25, minX - 60);

    const srcSideY = src.y + actualSrcH * 0.5;
    const tgtSideY = tgt.y + actualTgtH * 0.5;

    const pathD = `M ${src.x} ${srcSideY} L ${gutterX} ${srcSideY} L ${gutterX} ${tgtSideY} L ${tgt.x} ${tgtSideY}`;
    return {
      pathD,
      labelX: gutterX,
      labelY: (srcSideY + tgtSideY) / 2,
      isLoop: true,
    };
  }

  // 2. Horizontal side-by-side arrangement:
  // Target is clearly to the right of source and vertical ranges overlap
  const isHorizRight = tgtLeft >= srcRight - 10 && tgtBottom >= srcTop - 25 && tgtTop <= srcBottom + 25;
  if (isHorizRight) {
    const x1 = srcRight;
    const y1 = src.y + (edge.type === 'true' ? actualSrcH * 0.35 : edge.type === 'false' ? actualSrcH * 0.65 : actualSrcH * 0.5);
    const x2 = tgtLeft;
    const y2 = tgt.y + actualTgtH * 0.5;
    const midX = (x1 + x2) / 2;

    const pathD = `M ${x1} ${y1} L ${midX} ${y1} L ${midX} ${y2} L ${x2} ${y2}`;
    return {
      pathD,
      labelX: midX,
      labelY: (y1 + y2) / 2,
      isLoop: false,
    };
  }

  // Target is clearly to the left of source and vertical ranges overlap
  const isHorizLeft = tgtRight <= srcLeft + 10 && tgtBottom >= srcTop - 25 && tgtTop <= srcBottom + 25;
  if (isHorizLeft) {
    const x1 = srcLeft;
    const y1 = src.y + (edge.type === 'true' ? actualSrcH * 0.35 : edge.type === 'false' ? actualSrcH * 0.65 : actualSrcH * 0.5);
    const x2 = tgtRight;
    const y2 = tgt.y + actualTgtH * 0.5;
    const midX = (x1 + x2) / 2;

    const pathD = `M ${x1} ${y1} L ${midX} ${y1} L ${midX} ${y2} L ${x2} ${y2}`;
    return {
      pathD,
      labelX: midX,
      labelY: (y1 + y2) / 2,
      isLoop: false,
    };
  }

  // 3. Target is moved above source (user rearranged node upwards)
  if (tgtBottom <= srcTop + 15) {
    const x1 = src.x + (edge.type === 'true' ? src.width * 0.28 : edge.type === 'false' ? src.width * 0.72 : src.width * 0.5);
    const y1 = srcTop;
    const x2 = tgt.x + tgt.width * 0.5;
    const y2 = tgtBottom;

    if (Math.abs(x1 - x2) < 2) {
      const pathD = `M ${x1} ${y1} L ${x2} ${y2}`;
      return { pathD, labelX: x1, labelY: (y1 + y2) / 2, isLoop: false };
    }

    const midY = (y1 + y2) / 2;
    const pathD = `M ${x1} ${y1} L ${x1} ${midY} L ${x2} ${midY} L ${x2} ${y2}`;
    return {
      pathD,
      labelX: (x1 + x2) / 2,
      labelY: midY,
      isLoop: false,
    };
  }

  // 4. Downward forward flow (standard DAG execution order)
  let x1: number;
  if (edge.type === 'true') {
    x1 = src.x + src.width * 0.28;
  } else if (edge.type === 'false') {
    x1 = src.x + src.width * 0.72;
  } else {
    x1 = src.x + src.width * 0.5;
  }
  const y1 = srcBottom;

  // Connection point on tgt (top edge touches with zero gap)
  const x2 = tgt.x + tgt.width * 0.5;
  const y2 = tgtTop;

  // Intervening obstacle avoidance between y1 and y2
  const obstacles = allNodes.filter((n) => {
    if (n.id === src.id || n.id === tgt.id) return false;
    const nBottom = n.y + (measuredHeights[n.id] || n.height);
    const vOverlap = n.y < y2 - 8 && nBottom > y1 + 8;
    if (!vOverlap) return false;

    const minLineX = Math.min(x1, x2) - 15;
    const maxLineX = Math.max(x1, x2) + 15;
    const hOverlap = n.x + n.width >= minLineX && n.x <= maxLineX;
    return hOverlap;
  });

  if (obstacles.length > 0) {
    let bypassLeft = edge.type === 'true' || x1 <= x2;
    if (edge.type === 'false') bypassLeft = false;

    let gutterX: number;
    if (bypassLeft) {
      const minObsX = Math.min(src.x, tgt.x, ...obstacles.map((o) => o.x));
      gutterX = Math.max(25, minObsX - 45);
    } else {
      const maxObsX = Math.max(src.x + src.width, tgt.x + tgt.width, ...obstacles.map((o) => o.x + o.width));
      gutterX = maxObsX + 45;
    }

    const y_step_out = y1 + 16;
    const y_step_in = y2 - 16;

    const pathD = `M ${x1} ${y1} L ${x1} ${y_step_out} L ${gutterX} ${y_step_out} L ${gutterX} ${y_step_in} L ${x2} ${y_step_in} L ${x2} ${y2}`;

    return {
      pathD,
      labelX: gutterX,
      labelY: (y_step_out + y_step_in) / 2,
      isLoop: false,
    };
  }

  // Direct vertical connection
  if (Math.abs(x1 - x2) < 2) {
    return {
      pathD: `M ${x1} ${y1} L ${x2} ${y2}`,
      labelX: x1,
      labelY: (y1 + y2) / 2,
      isLoop: false,
    };
  }

  const midY = y1 + (y2 - y1) * 0.5;
  const pathD = `M ${x1} ${y1} L ${x1} ${midY} L ${x2} ${midY} L ${x2} ${y2}`;
  return {
    pathD,
    labelX: (x1 + x2) / 2,
    labelY: midY,
    isLoop: false,
  };
}

interface MinimapProps {
  nodes: LayoutNode[];
  canvasWidth: number;
  canvasHeight: number;
  pan: { x: number; y: number };
  zoom: number;
  containerWidth: number;
  containerHeight: number;
  selectedBlockId: string | null;
  onNavigate: (newPanX: number, newPanY: number) => void;
}

const CFGMinimap: React.FC<MinimapProps> = ({
  nodes,
  canvasWidth,
  canvasHeight,
  pan,
  zoom,
  containerWidth,
  containerHeight,
  selectedBlockId,
  onNavigate,
}) => {
  const mapW = 150;
  const mapH = 100;
  const scale = Math.min(mapW / Math.max(canvasWidth, 1), mapH / Math.max(canvasHeight, 1));

  const worldVx = -pan.x / zoom;
  const worldVy = -pan.y / zoom;
  const worldVw = containerWidth / zoom;
  const worldVh = containerHeight / zoom;

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
    const newPanX = -(targetWorldX * zoom - containerWidth / 2);
    const newPanY = -(targetWorldY * zoom - containerHeight / 2);
    onNavigate(newPanX, newPanY);
  };

  return (
    <div className="absolute right-3 bottom-3 z-20 bg-white/95 backdrop-blur-xs border border-slate-300 rounded-lg shadow-md p-1.5 pointer-events-auto select-none">
      <div className="text-[9px] font-mono font-bold text-slate-500 px-1 pb-1 border-b border-slate-100 flex items-center justify-between">
        <span>MINIMAP</span>
        <span className="text-[8px] text-slate-400 font-semibold">{Math.round(zoom * 100)}%</span>
      </div>
      <svg
        width={mapW}
        height={mapH}
        className="cursor-crosshair mt-1 bg-slate-50 rounded border border-slate-200"
        onClick={handleClick}
      >
        {nodes.map((node) => {
          const isSelected = node.block.id === selectedBlockId;
          const isEntry = node.block.index === 0;
          const isBranch = Boolean(node.block.is_conditional);
          const fill = isSelected ? '#4f46e5' : isEntry ? '#10b981' : isBranch ? '#8b5cf6' : '#94a3b8';
          return (
            <rect
              key={node.block.id}
              x={node.x * scale}
              y={node.y * scale}
              width={Math.max(5, node.width * scale)}
              height={Math.max(4, node.height * scale)}
              fill={fill}
              opacity={isSelected ? 1 : 0.75}
              rx={1}
            />
          );
        })}
        <rect
          x={vx}
          y={vy}
          width={vw}
          height={vh}
          fill="rgba(99, 102, 241, 0.15)"
          stroke="#4f46e5"
          strokeWidth="1.2"
          strokeDasharray="2 1"
          rx={1}
        />
      </svg>
    </div>
  );
};

export const SingleBinaryFlowCanvas: React.FC<SingleBinaryFlowCanvasProps> = ({
  blocks,
  edges,
  binaryName = 'Target Binary',
  onOpenXrefs,
  onJumpToAddress,
}) => {
  const { getRenamed, applyToInstruction } = useSymbolRenames();

  // Navigation state (Pan and Zoom)
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 50, y: 40 });
  const [zoom, setZoom] = useState<number>(0.9);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const dragStart = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // Custom dragged positions when layout is unlocked (unlocked by default for immediate node rearranging)
  const [isLayoutLocked, setIsLayoutLocked] = useState<boolean>(false);
  const [customPositions, setCustomPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const dragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // Selection & Search state
  const [selectedBlockId, setSelectedBlockId] = useState<string | null>(blocks[0]?.id || null);
  const [hoveredBlockId, setHoveredBlockId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedBlocks, setExpandedBlocks] = useState<Set<string>>(new Set());

  const containerRef = useRef<HTMLDivElement>(null);
  const [containerDimensions, setContainerDimensions] = useState({ width: 900, height: 700 });

  // Measured DOM heights for 100% 0-gap connection accuracy
  const [measuredHeights, setMeasuredHeights] = useState<Record<string, number>>({});
  const nodeRefs = useRef<Record<string, HTMLDivElement | null>>({});

  useEffect(() => {
    if (containerRef.current) {
      const { clientWidth, clientHeight } = containerRef.current;
      setContainerDimensions({ width: clientWidth || 900, height: clientHeight || 700 });
    }
  }, []);

  // Synchronously measure rendered DOM heights to ensure 0-gap edge connections
  useLayoutEffect(() => {
    const next: Record<string, number> = {};
    let changed = false;
    for (const [id, el] of Object.entries(nodeRefs.current)) {
      if (el) {
        const h = el.offsetHeight;
        next[id] = h;
        if (measuredHeights[id] !== h) {
          changed = true;
        }
      }
    }
    if (changed) {
      setMeasuredHeights(next);
    }
  });

  // Global mousemove / mouseup listeners for smooth dynamic node dragging
  useEffect(() => {
    if (!draggingNodeId) return;

    const handleGlobalMouseMove = (e: MouseEvent) => {
      const worldMouseX = (e.clientX - pan.x) / zoom;
      const worldMouseY = (e.clientY - pan.y) / zoom;
      // Clamp coordinates to keep node within visible canvas bounds
      const newX = Math.max(20, Math.round(worldMouseX - dragOffsetRef.current.x));
      const newY = Math.max(20, Math.round(worldMouseY - dragOffsetRef.current.y));
      setCustomPositions((prev) => ({
        ...prev,
        [draggingNodeId]: { x: newX, y: newY },
      }));
    };

    const handleGlobalMouseUp = () => {
      setDraggingNodeId(null);
    };

    window.addEventListener('mousemove', handleGlobalMouseMove);
    window.addEventListener('mouseup', handleGlobalMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleGlobalMouseMove);
      window.removeEventListener('mouseup', handleGlobalMouseUp);
    };
  }, [draggingNodeId, pan.x, pan.y, zoom]);

  // Compute graph coordinates
  const layout = useMemo(
    () => computeGraphCoordinates(blocks, edges, expandedBlocks),
    [blocks, edges, expandedBlocks]
  );

  // Position map incorporating custom dragged positions
  const posMap = useMemo(() => {
    const map: Record<string, LayoutNode> = {};
    layout.nodes.forEach((n) => {
      const custom = customPositions[n.block.id];
      map[n.block.id] = {
        ...n,
        x: custom ? custom.x : n.x,
        y: custom ? custom.y : n.y,
      };
    });
    return map;
  }, [layout, customPositions]);

  // Dynamic canvas bounds accounting for moved nodes
  const canvasWidth = useMemo(() => {
    let maxX = layout.canvasWidth;
    Object.values(posMap).forEach((n) => {
      if (n.x + n.width + 160 > maxX) {
        maxX = n.x + n.width + 160;
      }
    });
    return maxX;
  }, [layout.canvasWidth, posMap]);

  const canvasHeight = useMemo(() => {
    let maxY = layout.canvasHeight;
    Object.values(posMap).forEach((n) => {
      const h = measuredHeights[n.block.id] || n.height;
      if (n.y + h + 160 > maxY) {
        maxY = n.y + h + 160;
      }
    });
    return maxY;
  }, [layout.canvasHeight, posMap, measuredHeights]);

  // Auto-fit calculation
  const fitToView = () => {
    if (!containerRef.current) return;
    const cw = containerRef.current.clientWidth || 900;
    const ch = containerRef.current.clientHeight || 700;
    const scaleX = (cw - 80) / Math.max(canvasWidth, 1);
    const scaleY = (ch - 80) / Math.max(canvasHeight, 1);
    const fitScale = Math.min(1.2, Math.max(0.4, Math.min(scaleX, scaleY)));
    setZoom(fitScale);
    setPan({
      x: Math.max(40, (cw - canvasWidth * fitScale) / 2),
      y: 40,
    });
  };

  useEffect(() => {
    fitToView();
  }, [blocks]);

  // Canvas pan dragging
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('.block-card-interactive')) return;
    if ((e.target as HTMLElement).closest('svg') && (e.target as HTMLElement).closest('.cursor-crosshair')) return;
    setIsDragging(true);
    dragStart.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggingNodeId) return; // Handled by global window listener
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.current.x, y: e.clientY - dragStart.current.y });
  };

  const handleMouseUp = () => {
    if (draggingNodeId) {
      setDraggingNodeId(null);
    }
    setIsDragging(false);
  };

  // Wheel zoom handler centered on mouse
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const factor = e.deltaY < 0 ? 1.08 : 0.92;
      const newZoom = Math.min(2.5, Math.max(0.35, zoom * factor));
      setZoom(newZoom);
      const newPanX = mouseX - (mouseX - pan.x) * (newZoom / zoom);
      const newPanY = mouseY - (mouseY - pan.y) * (newZoom / zoom);
      setPan({ x: newPanX, y: newPanY });
    };

    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, [zoom, pan]);

  const allNodesList = useMemo(() => {
    return Object.values(posMap).map((n) => ({
      id: n.block.id,
      x: n.x,
      y: n.y,
      width: n.width,
      height: measuredHeights[n.block.id] || n.height,
    }));
  }, [posMap, measuredHeights]);

  // Selected block details & relations
  const selectedNode = useMemo(() => {
    return layout.nodes.find((n) => n.block.id === selectedBlockId);
  }, [layout.nodes, selectedBlockId]);

  const { incomingEdges, outgoingEdges } = useMemo(() => {
    if (!selectedBlockId) return { incomingEdges: [], outgoingEdges: [] };
    const inc = edges.filter((e) => e.target === selectedBlockId);
    const out = edges.filter((e) => e.source === selectedBlockId);
    return { incomingEdges: inc, outgoingEdges: out };
  }, [edges, selectedBlockId]);

  // Count search query matches
  const searchMatchCount = useMemo(() => {
    if (!searchQuery.trim()) return 0;
    const q = searchQuery.toLowerCase();
    let count = 0;
    blocks.forEach((b) => {
      if (
        b.label.toLowerCase().includes(q) ||
        b.start_addr.toLowerCase().includes(q) ||
        b.id.toLowerCase().includes(q)
      ) {
        count++;
      } else if (
        b.instructions?.some(
          (i) =>
            i.mnemonic?.toLowerCase().includes(q) ||
            i.op_str?.toLowerCase().includes(q) ||
            i.address?.toLowerCase().includes(q)
        )
      ) {
        count++;
      }
    });
    return count;
  }, [blocks, searchQuery]);

  const toggleExpandBlock = (blockId: string) => {
    setExpandedBlocks((prev) => {
      const next = new Set(prev);
      if (next.has(blockId)) {
        next.delete(blockId);
      } else {
        next.add(blockId);
      }
      return next;
    });
  };

  const jumpToBlock = (blockId: string) => {
    const node = posMap[blockId];
    if (node && containerRef.current) {
      setSelectedBlockId(blockId);
      const cw = containerRef.current.clientWidth || 900;
      const ch = containerRef.current.clientHeight || 700;
      setPan({
        x: cw / 2 - (node.x + node.width / 2) * zoom,
        y: ch / 2 - (node.y + node.height / 2) * zoom,
      });
    }
  };

  return (
    <div
      ref={containerRef}
      className="flex flex-col h-full bg-slate-50/60 rounded-xl border border-slate-200 overflow-hidden relative select-none shadow-sm"
    >
      {/* Canvas Top Bar */}
      <div className="px-4 py-2.5 bg-white border-b border-slate-200 flex flex-wrap items-center justify-between gap-3 z-10 shadow-xs">
        {/* Left Side: Binary Title & Counts */}
        <div className="flex items-center gap-2.5">
          <div className="p-1 rounded bg-indigo-50 border border-indigo-200 text-indigo-700 shrink-0">
            <Network className="w-3.5 h-3.5" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold font-mono text-slate-900 truncate max-w-[240px]">
              {binaryName}
            </span>
            <span className="text-[10px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
              {blocks.length} blocks • {edges.length} edges
            </span>
            {blocks[0] && (
              <span className="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-semibold hidden sm:inline">
                Entry: {getRenamed(blocks[0].label)} ({blocks[0].start_addr})
              </span>
            )}
            {!isLayoutLocked && (
              <span className="text-[10px] font-mono text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded font-bold flex items-center gap-1">
                <GripHorizontal className="w-3 h-3 text-amber-600" />
                Free Dragging Active
              </span>
            )}
          </div>
        </div>

        {/* Center: Jump Legend */}
        <div className="hidden xl:flex items-center gap-2.5 text-[10px] font-mono text-slate-500">
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-1.5 bg-emerald-500 rounded-sm" /> True (Green)
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-1.5 bg-rose-500 rounded-sm" /> False (Red)
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-1.5 bg-indigo-500 rounded-sm" /> Jump (Blue)
          </span>
          <span className="flex items-center gap-1">
            <Repeat className="w-2.5 h-2.5 text-purple-600" /> Loop (Purple)
          </span>
        </div>

        {/* Right Side: Tools, Search, Lock & Zoom */}
        <div className="flex items-center gap-2">
          {/* Search CFG */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search CFG..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-7 py-1 text-xs bg-slate-50 hover:bg-white focus:bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 w-32 sm:w-44 transition-colors font-mono"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
          {searchQuery && searchMatchCount > 0 && (
            <span className="text-[10px] font-mono text-indigo-700 bg-indigo-50 border border-indigo-200 px-1.5 py-0.5 rounded font-bold">
              {searchMatchCount} hits
            </span>
          )}

          {/* Lock / Unlock Layout Toggle */}
          <button
            onClick={() => setIsLayoutLocked(!isLayoutLocked)}
            className={`px-2.5 py-1 rounded-lg border text-xs font-mono font-medium flex items-center gap-1.5 transition-colors shadow-2xs ${
              !isLayoutLocked
                ? 'bg-amber-50 border-amber-300 text-amber-800 font-semibold'
                : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
            }`}
            title={isLayoutLocked ? 'Click to Unlock Node Dragging' : 'Layout Unlocked - Click to Lock'}
          >
            {isLayoutLocked ? (
              <Lock className="w-3.5 h-3.5 text-slate-400" />
            ) : (
              <Unlock className="w-3.5 h-3.5 text-amber-600" />
            )}
            <span>{isLayoutLocked ? 'Locked' : 'Unlocked'}</span>
          </button>

          {/* Reset Dragged Positions */}
          {Object.keys(customPositions).length > 0 && (
            <button
              onClick={() => setCustomPositions({})}
              className="px-2.5 py-1 rounded-lg bg-amber-50 border border-amber-300 text-amber-900 hover:bg-amber-100 text-xs font-mono font-semibold flex items-center gap-1.5 shadow-2xs transition-colors cursor-pointer"
              title="Reset all dragged node positions to auto DAG layout"
            >
              <RotateCcw className="w-3.5 h-3.5 text-amber-700" />
              <span>Reset Layout ({Object.keys(customPositions).length} moved)</span>
            </button>
          )}

          {/* Auto-Fit View */}
          <button
            onClick={fitToView}
            className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100 shadow-2xs transition-colors"
            title="Auto-Fit all blocks in view"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>

          {/* Zoom In & Out */}
          <div className="flex items-center bg-white border border-slate-200 rounded-lg p-0.5 shadow-2xs">
            <button
              onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}
              className="p-1 hover:bg-slate-100 rounded text-slate-600"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <span className="px-1.5 text-[11px] font-mono text-slate-600 font-medium">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom((z) => Math.max(0.35, z - 0.15))}
              className="p-1 hover:bg-slate-100 rounded text-slate-600"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Reset Pan */}
          <button
            onClick={() => setPan({ x: 50, y: 40 })}
            className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-slate-100 shadow-2xs transition-colors"
            title="Reset Pan"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <span className="text-[10px] text-slate-400 font-mono hidden md:inline">
            ({Math.round(pan.x)}, {Math.round(pan.y)})
          </span>
        </div>
      </div>

      {/* Pannable Canvas Container */}
      <div
        className="flex-1 overflow-hidden relative cursor-grab active:cursor-grabbing"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        {/* Subtle Canvas Dot Grid */}
        <svg className="w-full h-full absolute inset-0 pointer-events-none opacity-30">
          <defs>
            <pattern id="flow-grid-dots" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="0.8" fill="#94a3b8" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#flow-grid-dots)" />
        </svg>

        {/* Scaled & Panned Content */}
        <div
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
            width: canvasWidth,
            height: canvasHeight,
            position: 'absolute',
          }}
        >
          {/* SVG Connector Layer - Obstacle-Aware Routing with 0-Gap Touch */}
          <svg
            width={canvasWidth}
            height={canvasHeight}
            className="absolute inset-0 pointer-events-none"
            style={{ overflow: 'visible' }}
          >
            <defs>
              <marker id="arrowhead-true" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <polygon points="0 1, 8 4, 0 7" fill="#10b981" />
              </marker>
              <marker id="arrowhead-false" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <polygon points="0 1, 8 4, 0 7" fill="#ef4444" />
              </marker>
              <marker id="arrowhead-uncond" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <polygon points="0 1, 8 4, 0 7" fill="#6366f1" />
              </marker>
              <marker id="arrowhead-fallthrough" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <polygon points="0 1, 8 4, 0 7" fill="#94a3b8" />
              </marker>
              <marker id="arrowhead-loop" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                <polygon points="0 1, 9 4.5, 0 8" fill="#8b5cf6" />
              </marker>
            </defs>

            {/* Render all directed edges with obstacle avoidance and 90 degree turns */}
            {layout.edges.map((e, idx) => {
              const src = posMap[e.source];
              const tgt = posMap[e.target];
              if (!src || !tgt) return null;

              const edgeRes = computeEdgePathAndLabel(
                { id: src.block.id, x: src.x, y: src.y, width: src.width, height: src.height },
                { id: tgt.block.id, x: tgt.x, y: tgt.y, width: tgt.width, height: tgt.height },
                e,
                allNodesList,
                measuredHeights
              );

              const isLoop = edgeRes.isLoop;
              const isTrue = e.type === 'true';
              const isFalse = e.type === 'false';
              const isJmp = e.type === 'unconditional';

              const isEdgeHighlighted =
                selectedBlockId === e.source ||
                selectedBlockId === e.target ||
                hoveredBlockId === e.source ||
                hoveredBlockId === e.target;

              let strokeColor = '#94a3b8';
              let markerEnd = 'url(#arrowhead-fallthrough)';
              let strokeWidth = isEdgeHighlighted ? '3' : '2';
              let strokeDasharray: string | undefined = undefined;

              if (isLoop) {
                strokeColor = '#8b5cf6';
                markerEnd = 'url(#arrowhead-loop)';
                strokeWidth = isEdgeHighlighted ? '3.5' : '2.5';
                strokeDasharray = '6 3';
              } else if (isTrue) {
                strokeColor = '#10b981';
                markerEnd = 'url(#arrowhead-true)';
                strokeWidth = isEdgeHighlighted ? '3.5' : '2.5';
              } else if (isFalse) {
                strokeColor = '#ef4444';
                markerEnd = 'url(#arrowhead-false)';
                strokeWidth = isEdgeHighlighted ? '3.5' : '2.5';
              } else if (isJmp) {
                strokeColor = '#6366f1';
                markerEnd = 'url(#arrowhead-uncond)';
                strokeWidth = isEdgeHighlighted ? '3' : '2';
              }

              return (
                <g key={`edge_${idx}`} className={isEdgeHighlighted ? 'opacity-100' : 'opacity-85'}>
                  <path
                    d={edgeRes.pathD}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={strokeDasharray}
                    markerEnd={markerEnd}
                  />
                  {isTrue && (
                    <foreignObject x={edgeRes.labelX - 52} y={edgeRes.labelY - 13} width="104" height="26">
                      <div className="bg-emerald-100 text-emerald-900 border border-emerald-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded-md shadow-xs whitespace-nowrap flex items-center justify-center gap-1.5 leading-tight select-none">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
                        <span>True (Taken)</span>
                      </div>
                    </foreignObject>
                  )}
                  {isFalse && (
                    <foreignObject x={edgeRes.labelX - 40} y={edgeRes.labelY - 13} width="80" height="26">
                      <div className="bg-rose-100 text-rose-900 border border-rose-400 text-[10px] font-mono font-bold px-2 py-0.5 rounded-md shadow-xs whitespace-nowrap flex items-center justify-center gap-1.5 leading-tight select-none">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0" />
                        <span>False</span>
                      </div>
                    </foreignObject>
                  )}
                  {isJmp && (
                    <foreignObject x={edgeRes.labelX - 38} y={edgeRes.labelY - 13} width="76" height="26">
                      <div className="bg-indigo-100 text-indigo-900 border border-indigo-300 text-[10px] font-mono font-bold px-2 py-0.5 rounded-md shadow-xs whitespace-nowrap flex items-center justify-center gap-1.5 leading-tight select-none">
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0" />
                        <span>Jump</span>
                      </div>
                    </foreignObject>
                  )}
                  {isLoop && (
                    <foreignObject x={edgeRes.labelX - 43} y={edgeRes.labelY - 13} width="86" height="26">
                      <div className="bg-purple-100 text-purple-900 border border-purple-300 text-[10px] font-mono font-bold px-2 py-0.5 rounded-md shadow-xs whitespace-nowrap flex items-center justify-center gap-1 leading-tight select-none">
                        <Repeat className="w-2.5 h-2.5 text-purple-600 shrink-0" />
                        <span>LOOP</span>
                      </div>
                    </foreignObject>
                  )}
                </g>
              );
            })}
          </svg>

          {/* HTML Block Node Cards Layer */}
          {Object.values(posMap).map((node) => {
            const block = node.block;
            const isHovered = hoveredBlockId === block.id;
            const isSelected = selectedBlockId === block.id;
            const isBeingDragged = draggingNodeId === block.id;
            const isEntry = block.index === 0;

            // Search highlight
            const isSearchMatch = Boolean(
              searchQuery.trim() &&
                (block.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
                  block.start_addr.toLowerCase().includes(searchQuery.toLowerCase()) ||
                  block.instructions?.some(
                    (i) =>
                      i.mnemonic?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                      i.op_str?.toLowerCase().includes(searchQuery.toLowerCase())
                  ))
            );

            // Card styling
            const cardBorder = isEntry
              ? 'border-emerald-300 hover:border-emerald-500'
              : block.is_conditional
              ? 'border-indigo-300 hover:border-indigo-500'
              : 'border-slate-300 hover:border-slate-400';

            const headerBg = isEntry
              ? 'bg-emerald-50 text-emerald-900 border-b border-emerald-200'
              : block.is_conditional
              ? 'bg-indigo-50/70 text-indigo-900 border-b border-indigo-200'
              : 'bg-slate-50 text-slate-800 border-b border-slate-200';

            const badgeClass = isEntry
              ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
              : block.is_conditional
              ? 'bg-indigo-100 text-indigo-800 border-indigo-300'
              : 'bg-slate-100 text-slate-700 border-slate-200';

            const roleLabel = isEntry
              ? 'ENTRY'
              : block.is_conditional
              ? 'BRANCH'
              : `${block.instructions?.length || block.instruction_count || 0} INSTRS`;

            const isExpanded = expandedBlocks.has(block.id);
            const totalInstCount = block.instructions?.length || 0;
            const visibleInstructions = isExpanded
              ? block.instructions || []
              : (block.instructions || []).slice(0, 5);

            return (
              <div
                key={block.id}
                id={`canvas_${block.id}`}
                ref={(el) => {
                  nodeRefs.current[block.id] = el;
                }}
                style={{
                  position: 'absolute',
                  left: node.x,
                  top: node.y,
                  width: node.width,
                  cursor: !isLayoutLocked ? (isBeingDragged ? 'grabbing' : 'grab') : 'pointer',
                  userSelect: 'none',
                  touchAction: 'none',
                }}
                onMouseDown={(e) => {
                  if (!isLayoutLocked) {
                    e.stopPropagation();
                    setDraggingNodeId(block.id);
                    const worldMouseX = (e.clientX - pan.x) / zoom;
                    const worldMouseY = (e.clientY - pan.y) / zoom;
                    dragOffsetRef.current = {
                      x: worldMouseX - node.x,
                      y: worldMouseY - node.y,
                    };
                  }
                }}
                onMouseEnter={() => setHoveredBlockId(block.id)}
                onMouseLeave={() => setHoveredBlockId(null)}
                onClick={() => setSelectedBlockId(block.id)}
                className={`block-card-interactive bg-white rounded-lg border shadow-xs transition-shadow duration-150 overflow-hidden ${cardBorder} ${
                  isSelected ? 'ring-2 ring-indigo-500 shadow-md scale-[1.01]' : isHovered ? 'ring-1 ring-indigo-400' : ''
                } ${isBeingDragged ? 'ring-2 ring-amber-500 shadow-xl opacity-95 z-30' : 'z-10'} ${
                  isSearchMatch ? 'ring-2 ring-yellow-400' : ''
                }`}
              >
                {/* Block Header */}
                <div className={`px-2.5 py-1.5 flex items-center justify-between font-mono text-[11px] ${headerBg}`}>
                  <div className="flex items-center gap-1.5 truncate">
                    {!isLayoutLocked && (
                      <span title="Drag to reposition block">
                        <GripHorizontal className="w-3.5 h-3.5 text-slate-400 shrink-0 cursor-grab" />
                      </span>
                    )}
                    <span className="font-bold text-slate-900">{getRenamed(block.label)}</span>
                    <span className="text-[9px] text-slate-500">
                      ({block.start_addr})
                    </span>
                  </div>
                  <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold border shrink-0 ${badgeClass}`}>
                    {roleLabel}
                  </span>
                </div>

                {/* Badges for Loops and Branching */}
                {(block.has_loop_exit || block.is_loop_target || block.is_conditional) && (
                  <div className="px-2 py-0.5 bg-slate-50 border-b border-slate-100 flex items-center gap-1 flex-wrap">
                    {block.is_loop_target && (
                      <span className="px-1.5 py-0.2 rounded text-[8px] font-mono font-bold bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-0.5">
                        <Repeat className="w-2.5 h-2.5" /> Loop Target
                      </span>
                    )}
                    {block.has_loop_exit && (
                      <span className="px-1.5 py-0.2 rounded text-[8px] font-mono font-bold bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-0.5">
                        <Repeat className="w-2.5 h-2.5" /> Loop Exit
                      </span>
                    )}
                    {block.is_conditional && (
                      <span className="px-1.5 py-0.2 rounded text-[8px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200 flex items-center gap-0.5">
                        <Split className="w-2.5 h-2.5" /> If / Branch
                      </span>
                    )}
                  </div>
                )}

                {/* Disassembly Instructions preview with Semantic Highlighting */}
                <div className="divide-y divide-slate-100 font-mono text-[10px]">
                  {visibleInstructions.map((rawInst, iIdx) => {
                    const inst = applyToInstruction(rawInst);
                    const mne = inst.mnemonic?.toLowerCase() || '';

                    let mneColor = 'text-indigo-700 font-bold';
                    if (mne === 'call') mneColor = 'text-purple-600 font-bold';
                    else if (mne.startsWith('j') && mne !== 'jmp') mneColor = 'text-emerald-600 font-bold';
                    else if (mne === 'jmp') mneColor = 'text-blue-600 font-bold';
                    else if (mne.startsWith('ret')) mneColor = 'text-amber-600 font-bold';
                    else if (['mov', 'lea', 'push', 'pop', 'xor', 'add', 'sub', 'cmp', 'test'].includes(mne)) {
                      mneColor = 'text-slate-800 font-semibold';
                    }

                    const isInstSearchHit = Boolean(
                      searchQuery.trim() &&
                        (inst.mnemonic?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          inst.op_str?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          inst.address?.toLowerCase().includes(searchQuery.toLowerCase()))
                    );

                    return (
                      <div
                        key={iIdx}
                        className={`px-2 py-0.5 flex items-center justify-between gap-1.5 hover:bg-slate-50 text-slate-800 ${
                          isInstSearchHit ? 'bg-amber-100/80 font-semibold' : ''
                        }`}
                      >
                        <div className="flex items-center gap-1.5 truncate">
                          <span className="text-[9px] text-slate-400 w-14 shrink-0 select-none">
                            {inst.address}
                          </span>
                          <span className={`w-10 shrink-0 ${mneColor}`}>{inst.mnemonic}</span>
                          <span className="text-slate-700 truncate">{inst.op_str}</span>
                        </div>
                        {/* Interactive XREF / Jump Trigger */}
                        {inst.op_str && (onJumpToAddress || onOpenXrefs) && (mne === 'call' || mne.startsWith('j')) && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (onOpenXrefs && inst.op_str) {
                                onOpenXrefs(inst.op_str);
                              } else if (onJumpToAddress && inst.op_str) {
                                onJumpToAddress(inst.op_str);
                              }
                            }}
                            className="text-[8px] text-indigo-500 hover:text-indigo-800 hover:underline shrink-0"
                            title="Inspect Target XREFs"
                          >
                            xref
                          </button>
                        )}
                      </div>
                    );
                  })}

                  {/* Expand / Collapse Instructions Button */}
                  {totalInstCount > 5 && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpandBlock(block.id);
                      }}
                      className="w-full px-2 py-0.5 text-[9px] text-indigo-600 hover:text-indigo-800 text-center bg-slate-50/70 hover:bg-slate-100 transition-colors flex items-center justify-center gap-1"
                    >
                      {isExpanded ? (
                        <span>▲ Show fewer</span>
                      ) : (
                        <span>▼ +{totalInstCount - 5} more instructions</span>
                      )}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Minimap in lower-right corner */}
        <CFGMinimap
          nodes={Object.values(posMap)}
          canvasWidth={canvasWidth}
          canvasHeight={canvasHeight}
          pan={pan}
          zoom={zoom}
          containerWidth={containerDimensions.width}
          containerHeight={containerDimensions.height}
          selectedBlockId={selectedBlockId}
          onNavigate={(newPanX, newPanY) => setPan({ x: newPanX, y: newPanY })}
        />
      </div>

      {/* Selected Block Inspection Footer Bar */}
      {selectedNode && (
        <div className="px-4 py-2 bg-white border-t border-slate-200 flex flex-wrap items-center justify-between gap-3 text-xs z-10 shadow-xs">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 font-mono">
              <span className="font-bold text-slate-900">{getRenamed(selectedNode.block.label)}</span>
              <span className="text-slate-400">({selectedNode.block.start_addr})</span>
            </div>

            {/* Predecessors Jump Pills */}
            <div className="flex items-center gap-1 text-[11px] font-mono">
              <span className="text-slate-400 flex items-center gap-0.5">
                <ArrowLeft className="w-3 h-3 text-slate-400" /> From:
              </span>
              {incomingEdges.length === 0 ? (
                <span className="text-slate-400 italic">None (Root)</span>
              ) : (
                incomingEdges.map((ie, iIdx) => (
                  <button
                    key={iIdx}
                    onClick={() => jumpToBlock(ie.source)}
                    className="px-1.5 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 font-semibold"
                    title={`Jump to predecessor ${ie.source}`}
                  >
                    {getRenamed(ie.source)}
                  </button>
                ))
              )}
            </div>

            {/* Successors Jump Pills */}
            <div className="flex items-center gap-1 text-[11px] font-mono">
              <span className="text-slate-400 flex items-center gap-0.5">
                <ArrowRight className="w-3 h-3 text-slate-400" /> To:
              </span>
              {outgoingEdges.length === 0 ? (
                <span className="text-slate-400 italic">None (Terminal)</span>
              ) : (
                outgoingEdges.map((oe, oIdx) => (
                  <button
                    key={oIdx}
                    onClick={() => jumpToBlock(oe.target)}
                    className={`px-1.5 py-0.5 rounded border font-semibold ${
                      oe.type === 'true'
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200 hover:bg-emerald-100'
                        : oe.type === 'false'
                        ? 'bg-rose-50 text-rose-800 border-rose-200 hover:bg-rose-100'
                        : 'bg-indigo-50 text-indigo-800 border-indigo-200 hover:bg-indigo-100'
                    }`}
                    title={`Jump to successor ${oe.target} (${oe.type})`}
                  >
                    {getRenamed(oe.target)} ({oe.type})
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {onOpenXrefs && (
              <button
                onClick={() => onOpenXrefs(selectedNode.block.label)}
                className="px-2.5 py-1 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 font-semibold text-[11px] flex items-center gap-1 transition-colors"
                title="Inspect Cross-References for this block"
              >
                <Layers className="w-3 h-3" />
                <span>Block XREFs</span>
              </button>
            )}
            {onJumpToAddress && (
              <button
                onClick={() => onJumpToAddress(selectedNode.block.start_addr)}
                className="px-2.5 py-1 rounded-lg bg-slate-50 hover:bg-slate-100 text-slate-700 border border-slate-200 font-semibold text-[11px] flex items-center gap-1 transition-colors"
                title="Jump to Disassembly view"
              >
                <ExternalLink className="w-3 h-3" />
                <span>View Asm</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
