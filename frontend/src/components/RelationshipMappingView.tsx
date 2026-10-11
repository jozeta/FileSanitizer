import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Network,
  GitCompare,
  Clock,
  Hash,
  Globe,
  ShieldAlert,
  Download,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Copy,
  Check,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  User,
  Activity,
  Sparkles,
  Server,
  Terminal,
  Key,
  Repeat,
  Layers,
  Move,
  ArrowUpDown,
  Radio,
  Search,
  RefreshCw,
  SlidersHorizontal,
  Eye,
  EyeOff,
  CheckSquare,
  Link2
} from 'lucide-react';
import {
  IncidentCorrelationData,
  WorkspaceJob
} from '../types';
import { apiClient } from '../api/client';
import { BinDiffViewer } from './BinDiffViewer';
import { EvtxTriageCard } from './EvtxTriageCard';
import { MultiEvtxSwimlaneView } from './MultiEvtxSwimlaneView';
import { ReferencedText } from './ReferencedFileLink';

interface RelationshipMappingViewProps {
  jobs: WorkspaceJob[];
  cachedData?: IncidentCorrelationData | null;
  onDataLoaded?: (data: IncidentCorrelationData) => void;
  onSelectJob: (jobId: string) => void;
}

type SubViewType = 'graph' | 'bindiff' | 'evtx_fleet' | 'pcap_fleet' | 'timeline' | 'hashes' | 'infrastructure' | 'mitre' | 'cross_refs';

export const RelationshipMappingView: React.FC<RelationshipMappingViewProps> = ({
  jobs,
  cachedData,
  onDataLoaded,
  onSelectJob,
}) => {
  const [data, setData] = useState<IncidentCorrelationData | null>(() => cachedData || null);
  const [loading, setLoading] = useState<boolean>(() => !cachedData);
  const [error, setError] = useState<string | null>(null);
  const [activeSubView, setActiveSubView] = useState<SubViewType>('graph');
  const [evtxFleetTab, setEvtxFleetTab] = useState<'unified' | 'analytics'>('unified');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Timeline search and filtering state
  const [timelineSearch, setTimelineSearch] = useState<string>('');
  const [selectedTimelineFile, setSelectedTimelineFile] = useState<string>('all');
  const [selectedTimelineHost, setSelectedTimelineHost] = useState<string>('all');
  const [anomaliesOnly, setAnomaliesOnly] = useState<boolean>(false);
  const [timelineViewMode, setTimelineViewMode] = useState<'table' | 'swimlanes'>('table');

  // Identify EVTX log files for multi-host vertical swimlane view
  const evtxJobs = useMemo(() => {
    return (jobs || []).filter((j: any) => {
      const fn = (j.filename || '').toLowerCase();
      const origFn = (j.original_filename || '').toLowerCase();
      return (
        j.category === 'evtx' ||
        fn.endsWith('.evtx') ||
        origFn.endsWith('.evtx') ||
        j.evtx_info != null ||
        (j.analysis_data && j.analysis_data.evtx != null)
      );
    });
  }, [jobs]);

  // Graph state & interaction
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const ALL_THREAT_FILTER_KEYS = useMemo(() => ['hosts', 'hashes', 'timestamps', 'vulns', 'geo', 'network', 'identity', 'ttps', 'artifacts'], []);
  const [selectedFilters, setSelectedFilters] = useState<string[]>(['hosts', 'hashes', 'timestamps', 'vulns', 'geo', 'network', 'identity', 'ttps', 'artifacts']);
  const [sharedOnlyFilter, setSharedOnlyFilter] = useState<boolean>(false);
  const [layoutMode, setLayoutMode] = useState<'radial' | 'category' | 'sample' | 'format' | 'hierarchical' | 'grid'>('radial');
  const [sortMode, setSortMode] = useState<'connectivity' | 'threat_severity' | 'alpha' | 'reverse_alpha' | 'type' | 'shared_first'>('connectivity');
  const [nodeProximity, setNodeProximity] = useState<'close' | 'middle' | 'far' | 'very_far'>('middle');
  const [hideIsolatedNodes, setHideIsolatedNodes] = useState<boolean>(false);
  const [hideBenignNodes, setHideBenignNodes] = useState<boolean>(false);
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(new Set());

  const [graphZoom, setGraphZoom] = useState<number>(1);
  const [graphPan, setGraphPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [categoryClusterLabels, setCategoryClusterLabels] = useState<{ key: string; label: string; count: number; x: number; y: number }[]>([]);
  const [canvasSize, setCanvasSize] = useState<{ width: number; height: number }>({ width: 1300, height: 700 });
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // Draggable nodes mechanics (multi-node group dragging supported)
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const nodeDragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const nodeMouseDownPosRef = useRef<{ x: number; y: number } | null>(null);
  const hasDraggedNodeRef = useRef<boolean>(false);
  const dragInitialPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const dragOriginWorldRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  const clientToWorld = (clientX: number, clientY: number) => {
    const svgEl = svgRef.current;
    if (!svgEl) return { x: clientX, y: clientY };
    const rect = svgEl.getBoundingClientRect();
    return {
      x: (clientX - rect.left - graphPan.x) / graphZoom,
      y: (clientY - rect.top - graphPan.y) / graphZoom,
    };
  };

  const handleNodeMouseDown = (e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    setDraggingNodeId(nodeId);
    hasDraggedNodeRef.current = false;
    nodeMouseDownPosRef.current = { x: e.clientX, y: e.clientY };
    const worldPos = clientToWorld(e.clientX, e.clientY);
    dragOriginWorldRef.current = worldPos;
    dragInitialPositionsRef.current = { ...nodePositions };

    const nodePos = nodePositions[nodeId] || { x: 0, y: 0 };
    nodeDragOffsetRef.current = {
      x: worldPos.x - nodePos.x,
      y: worldPos.y - nodePos.y,
    };

    if (e.shiftKey) {
      setSelectedNodeIds((prev) => {
        const next = new Set(prev);
        if (next.has(nodeId)) {
          next.delete(nodeId);
        } else {
          next.add(nodeId);
        }
        return next;
      });
    } else if (!selectedNodeIds.has(nodeId)) {
      setSelectedNodeIds(new Set([nodeId]));
    }
  };

  const handleCanvasMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    dragStartRef.current = { x: e.clientX - graphPan.x, y: e.clientY - graphPan.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggingNodeId) {
      if (nodeMouseDownPosRef.current) {
        const dist = Math.hypot(e.clientX - nodeMouseDownPosRef.current.x, e.clientY - nodeMouseDownPosRef.current.y);
        if (dist > 3) hasDraggedNodeRef.current = true;
      }
      const worldPos = clientToWorld(e.clientX, e.clientY);

      // Multi-node simultaneous drag
      if (selectedNodeIds.has(draggingNodeId) && selectedNodeIds.size > 1) {
        const dx = worldPos.x - dragOriginWorldRef.current.x;
        const dy = worldPos.y - dragOriginWorldRef.current.y;
        setNodePositions((prev) => {
          const next = { ...prev };
          selectedNodeIds.forEach((id) => {
            const initPos = dragInitialPositionsRef.current[id] || prev[id];
            if (initPos) {
              next[id] = { x: initPos.x + dx, y: initPos.y + dy };
            }
          });
          return next;
        });
        return;
      }

      // Single node drag
      const newX = worldPos.x - nodeDragOffsetRef.current.x;
      const newY = worldPos.y - nodeDragOffsetRef.current.y;
      setNodePositions((prev) => ({
        ...prev,
        [draggingNodeId]: { x: newX, y: newY },
      }));
      return;
    }
    if (isPanning) {
      setGraphPan({
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y,
      });
    }
  };

  const handleMouseUp = () => {
    setDraggingNodeId(null);
    setIsPanning(false);
  };

  // Node styling matching EntityGraphCard
  const getNodeStyling = (node: any) => {
    if (node.type === 'file') {
      return { fill: '#eef2ff', stroke: '#6366f1', text: '#4338ca', badge: 'bg-indigo-50 text-indigo-700 border-indigo-200' };
    }
    if (node.type === 'host') {
      return { fill: '#f0fdf4', stroke: '#16a34a', text: '#15803d', badge: 'bg-green-50 text-green-700 border-green-200' };
    }
    if (node.type === 'hash') {
      return { fill: '#ecfdf5', stroke: '#10b981', text: '#047857', badge: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
    }
    if (node.type === 'timestamp') {
      return { fill: '#fff7ed', stroke: '#f97316', text: '#c2410c', badge: 'bg-orange-50 text-orange-700 border-orange-200' };
    }
    if (node.type === 'vulnerability') {
      return { fill: '#fff1f2', stroke: '#e11d48', text: '#be123c', badge: 'bg-rose-50 text-rose-700 border-rose-200' };
    }
    if (node.type === 'geolocation') {
      return { fill: '#ecfeff', stroke: '#06b6d4', text: '#0e7490', badge: 'bg-cyan-50 text-cyan-700 border-cyan-200' };
    }
    if (node.type === 'ip') {
      return { fill: '#f0f9ff', stroke: '#0ea5e9', text: '#0369a1', badge: 'bg-sky-50 text-sky-700 border-sky-200' };
    }
    if (node.type === 'domain' || node.type === 'url') {
      return { fill: '#f0fdfa', stroke: '#14b8a6', text: '#0f766e', badge: 'bg-teal-50 text-teal-700 border-teal-200' };
    }
    if (node.type === 'user') {
      return { fill: '#fffbeb', stroke: '#f59e0b', text: '#b45309', badge: 'bg-amber-50 text-amber-700 border-amber-200' };
    }
    if (node.type === 'technique') {
      return { fill: '#fff1f2', stroke: '#f43f5e', text: '#be123c', badge: 'bg-rose-50 text-rose-700 border-rose-200' };
    }
    if (node.type === 'artifact') {
      return { fill: '#f5f3ff', stroke: '#8b5cf6', text: '#6d28d9', badge: 'bg-violet-50 text-violet-700 border-violet-200' };
    }
    return { fill: '#f8fafc', stroke: '#64748b', text: '#334155', badge: 'bg-slate-100 text-slate-700 border-slate-200' };
  };

  const fetchCorrelation = async () => {
    const jobIds = (jobs || []).map((j: any) => j?.jobId || j?.job_id).filter(Boolean);
    if (jobIds.length === 0) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.correlateJobs(jobIds);
      setData(res);
      if (onDataLoaded) onDataLoaded(res);
      layoutGraphNodes(res.campaign_graph?.nodes || [], res.campaign_graph?.edges || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load correlation data.');
    } finally {
      setLoading(false);
    }
  };

  // Fetch correlation data when jobs change
  useEffect(() => {
    let isMounted = true;

    if (cachedData && cachedData.files && cachedData.files.length === jobs.length) {
      setData(cachedData);
      setLoading(false);
      setError(null);
      layoutGraphNodes(cachedData.campaign_graph?.nodes || [], cachedData.campaign_graph?.edges || []);
      return;
    }

    if (!jobs || jobs.length === 0) {
      setLoading(false);
      return;
    }

    const runFetch = async () => {
      const jobIds = (jobs || []).map((j: any) => j?.jobId || j?.job_id).filter(Boolean);
      if (jobIds.length === 0) return;
      setLoading(true);
      setError(null);
      try {
        const res = await apiClient.correlateJobs(jobIds);
        if (isMounted) {
          setData(res);
          if (onDataLoaded) onDataLoaded(res);
          layoutGraphNodes(res.campaign_graph?.nodes || [], res.campaign_graph?.edges || []);
        }
      } catch (err: any) {
        if (isMounted) {
          setError(err.message || 'Failed to load correlation data.');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    runFetch();
    return () => {
      isMounted = false;
    };
  }, [jobs, cachedData]);

  // Multi-Layout & Multi-Sorting Graph Engine (Enhanced Generous Spacing & Collision Relaxation)
  const calculateLayout = (
    nodes: any[],
    edges: any[],
    layout: 'radial' | 'category' | 'sample' | 'format' | 'hierarchical' | 'grid',
    sort: 'connectivity' | 'threat_severity' | 'alpha' | 'reverse_alpha' | 'type' | 'shared_first',
    cWidth?: number,
    cHeight?: number,
    proximity: 'close' | 'middle' | 'far' | 'very_far' = 'middle'
  ): { positions: Record<string, { x: number; y: number }>; clusterLabels: { key: string; label: string; count: number; x: number; y: number }[] } => {
    const positions: Record<string, { x: number; y: number }> = {};
    const clusterLabels: { key: string; label: string; count: number; x: number; y: number }[] = [];
    if (!nodes || nodes.length === 0) return { positions, clusterLabels };

    const proximityMultipliers: Record<string, number> = {
      close: 0.65,
      middle: 1.0,
      far: 1.6,
      very_far: 2.4,
    };
    const prox = proximityMultipliers[proximity || 'middle'] || 1.0;

    const width = Math.max(1200, cWidth || 1300);
    const height = Math.max(620, cHeight || 650);
    const centerX = width / 2;
    const centerY = Math.round(height * 0.44);

    // Node degree calculation for connectivity sorting
    const degreeMap: Record<string, number> = {};
    edges.forEach((e) => {
      degreeMap[e.source] = (degreeMap[e.source] || 0) + 1;
      degreeMap[e.target] = (degreeMap[e.target] || 0) + 1;
    });

    const getSeverityScore = (n: any) => {
      if (n.type === 'vulnerability') return 100;
      if (n.type === 'technique') return 80;
      if (n.is_shared) return 60;
      if (n.type === 'file') return 50;
      if (n.type === 'artifact') return 40;
      if (['ip', 'domain', 'url'].includes(n.type)) return 30;
      return 10;
    };

    const sortNodesList = (list: any[]) => {
      return [...list].sort((a, b) => {
        if (sort === 'connectivity') {
          const degDiff = (degreeMap[b.id] || 0) - (degreeMap[a.id] || 0);
          if (degDiff !== 0) return degDiff;
          return (a.label || '').localeCompare(b.label || '');
        }
        if (sort === 'threat_severity') {
          const scoreDiff = getSeverityScore(b) - getSeverityScore(a);
          if (scoreDiff !== 0) return scoreDiff;
          return (a.label || '').localeCompare(b.label || '');
        }
        if (sort === 'alpha') {
          return (a.label || '').localeCompare(b.label || '');
        }
        if (sort === 'reverse_alpha') {
          return (b.label || '').localeCompare(a.label || '');
        }
        if (sort === 'type') {
          const typeComp = (a.type || '').localeCompare(b.type || '');
          if (typeComp !== 0) return typeComp;
          return (a.label || '').localeCompare(b.label || '');
        }
        if (sort === 'shared_first') {
          const sharedDiff = (b.is_shared ? 1 : 0) - (a.is_shared ? 1 : 0);
          if (sharedDiff !== 0) return sharedDiff;
          return (degreeMap[b.id] || 0) - (degreeMap[a.id] || 0);
        }
        return 0;
      });
    };

    const sortedNodes = sortNodesList(nodes);

    if (layout === 'radial') {
      // 1. RADIAL ORBIT (File hubs at center, all artifacts in orbit sorted by type/connectivity)
      const fileNodes = sortedNodes.filter((n) => n.type === 'file');
      const nonFileNodes = sortedNodes.filter((n) => n.type !== 'file');

      // File hubs with spacious separation
      if (fileNodes.length === 1) {
        positions[fileNodes[0].id] = { x: centerX, y: centerY };
      } else if (fileNodes.length === 2) {
        const offset = Math.round(120 * prox);
        positions[fileNodes[0].id] = { x: centerX - offset, y: centerY };
        positions[fileNodes[1].id] = { x: centerX + offset, y: centerY };
      } else {
        const fileRadius = Math.max(110 * prox, fileNodes.length * 48 * prox);
        fileNodes.forEach((node, idx) => {
          const angle = (idx / (fileNodes.length || 1)) * 2 * Math.PI - Math.PI / 2;
          positions[node.id] = {
            x: centerX + fileRadius * Math.cos(angle),
            y: centerY + fileRadius * 0.8 * Math.sin(angle),
          };
        });
      }

      // Non-file entities arranged by sort/type
      const count = nonFileNodes.length;
      if (count <= 10) {
        const rx = Math.min(width * 0.44, Math.max(220 * prox, count * 36 * prox));
        const ry = Math.min(height * 0.38, Math.max(140 * prox, count * 22 * prox));
        nonFileNodes.forEach((node, idx) => {
          const angle = (idx / (count || 1)) * 2 * Math.PI - Math.PI / 2;
          positions[node.id] = {
            x: centerX + rx * Math.cos(angle),
            y: centerY + ry * Math.sin(angle),
          };
        });
      } else {
        const innerCount = Math.ceil(count * 0.4);
        const outerCount = count - innerCount;
        const orbit1Rx = Math.min(width * 0.38, Math.max(200 * prox, innerCount * 24 * prox));
        const orbit1Ry = Math.min(height * 0.32, Math.max(130 * prox, innerCount * 16 * prox));
        const orbit2Rx = Math.min(width * 0.48, Math.max(340 * prox, outerCount * 22 * prox));
        const orbit2Ry = Math.min(height * 0.42, Math.max(220 * prox, outerCount * 14 * prox));

        nonFileNodes.forEach((node, idx) => {
          if (idx < innerCount) {
            const angle = (idx / (innerCount || 1)) * 2 * Math.PI - Math.PI / 2;
            positions[node.id] = {
              x: centerX + orbit1Rx * Math.cos(angle),
              y: centerY + orbit1Ry * Math.sin(angle),
            };
          } else {
            const outIdx = idx - innerCount;
            const angle = (outIdx / (outerCount || 1)) * 2 * Math.PI - Math.PI / 2;
            positions[node.id] = {
              x: centerX + orbit2Rx * Math.cos(angle),
              y: centerY + orbit2Ry * Math.sin(angle),
            };
          }
        });
      }
    } else if (layout === 'category') {
      // 2. GROUP BY CATEGORY / ENTITY TYPE (Clusters per entity category)
      const groups: Record<string, any[]> = {};
      sortedNodes.forEach((n) => {
        const key = ['ip', 'domain', 'url'].includes(n.type) ? 'network' : n.type;
        if (!groups[key]) groups[key] = [];
        groups[key].push(n);
      });

      const activeGroupKeys = Object.keys(groups);
      const otherKeys = activeGroupKeys.filter((k) => k !== 'file');
      const clusterCenters: Record<string, { x: number; y: number }> = {};

      if (activeGroupKeys.includes('file')) {
        clusterCenters['file'] = { x: centerX, y: centerY - 10 };
      }

      const totalOther = otherKeys.length;
      if (totalOther === 1) {
        clusterCenters[otherKeys[0]] = { x: centerX, y: centerY + 180 * prox };
      } else if (totalOther === 2) {
        clusterCenters[otherKeys[0]] = { x: centerX - 360 * prox, y: centerY };
        clusterCenters[otherKeys[1]] = { x: centerX + 360 * prox, y: centerY };
      } else {
        const clusterRadiusX = Math.min(width * 0.44, Math.max(340 * prox, totalOther * 65 * prox));
        const clusterRadiusY = Math.min(height * 0.36, Math.max(150 * prox, totalOther * 30 * prox));
        otherKeys.forEach((key, idx) => {
          const angle = (idx / totalOther) * 2 * Math.PI - Math.PI / 2;
          clusterCenters[key] = {
            x: centerX + clusterRadiusX * Math.cos(angle),
            y: centerY + clusterRadiusY * Math.sin(angle),
          };
        });
      }

      activeGroupKeys.forEach((key) => {
        const center = clusterCenters[key];
        const groupNodes = groups[key];
        const count = groupNodes.length;

        let maxSubRadius = 40 * prox;

        if (count === 1) {
          positions[groupNodes[0].id] = { x: center.x, y: center.y };
        } else if (count <= 4) {
          const subRadius = 65 * prox;
          maxSubRadius = subRadius;
          groupNodes.forEach((node, nIdx) => {
            const angle = (nIdx / count) * 2 * Math.PI;
            positions[node.id] = {
              x: center.x + subRadius * Math.cos(angle),
              y: center.y + subRadius * Math.sin(angle),
            };
          });
        } else if (count <= 7) {
          const subRadius = 95 * prox;
          maxSubRadius = subRadius;
          groupNodes.forEach((node, nIdx) => {
            const angle = (nIdx / count) * 2 * Math.PI;
            positions[node.id] = {
              x: center.x + subRadius * Math.cos(angle),
              y: center.y + subRadius * Math.sin(angle),
            };
          });
        } else {
          const innerCount = Math.min(3, Math.floor(count / 3));
          const outerCount = count - innerCount;
          const innerRadius = 55 * prox;
          const outerRadius = 120 * prox;
          maxSubRadius = outerRadius;

          groupNodes.forEach((node, nIdx) => {
            if (nIdx < innerCount) {
              const angle = (nIdx / innerCount) * 2 * Math.PI;
              positions[node.id] = {
                x: center.x + innerRadius * Math.cos(angle),
                y: center.y + innerRadius * Math.sin(angle),
              };
            } else {
              const outIdx = nIdx - innerCount;
              const angle = (outIdx / outerCount) * 2 * Math.PI;
              positions[node.id] = {
                x: center.x + outerRadius * Math.cos(angle),
                y: center.y + outerRadius * Math.sin(angle),
              };
            }
          });
        }

        let label = key.toUpperCase();
        if (key === 'file') label = 'FILE SAMPLES';
        if (key === 'hash') label = 'HASHES';
        if (key === 'timestamp') label = 'TIMESTAMPS';
        if (key === 'vulnerability') label = 'VULNERABILITIES';
        if (key === 'network') label = 'NETWORK IOCS';
        if (key === 'geolocation') label = 'GEOLOCATION';
        if (key === 'user') label = 'USER ACCOUNTS';
        if (key === 'technique') label = 'ATT&CK TECHNIQUES';
        if (key === 'artifact') label = 'TOOLS & APIS';
        clusterLabels.push({ key, label, count: groupNodes.length, x: center.x, y: center.y - maxSubRadius - 20 });
      });
    } else if (layout === 'sample') {
      // 3. GROUP BY ANALYZED FILE (All artifacts that belong to each file cluster tightly around that file)
      const fileNodes = sortedNodes.filter((n) => n.type === 'file');
      const nonFileNodes = sortedNodes.filter((n) => n.type !== 'file');
      const sharedEntities = nonFileNodes.filter((n) => n.is_shared);
      const nonSharedEntities = nonFileNodes.filter((n) => !n.is_shared);

      if (fileNodes.length <= 2) {
        const leftFile = fileNodes[0];
        const rightFile = fileNodes[1] || null;

        const fileOffset = Math.min(width * 0.34, 380 * prox);
        if (leftFile) positions[leftFile.id] = { x: centerX - fileOffset, y: centerY };
        if (rightFile) positions[rightFile.id] = { x: centerX + fileOffset, y: centerY };

        // Shared nodes centered vertically in corridor
        const sharedCount = sharedEntities.length;
        if (sharedCount > 0) {
          const ySpan = Math.min(height - 180, Math.max(140 * prox, sharedCount * 65 * prox));
          const startY = centerY - ySpan / 2;
          const stepY = sharedCount > 1 ? ySpan / (sharedCount - 1) : 0;
          sharedEntities.forEach((node, idx) => {
            const xOffset = sharedCount > 5 ? (idx % 2 === 0 ? -40 * prox : 40 * prox) : 0;
            positions[node.id] = {
              x: centerX + xOffset,
              y: sharedCount === 1 ? centerY : startY + idx * stepY,
            };
          });
        }

        // Left & right unique entities placed directly around their parent file
        const leftEntities = nonSharedEntities.filter((n) =>
          edges.some((e) => (e.source === leftFile?.id && e.target === n.id) || (e.target === leftFile?.id && e.source === n.id))
        );
        const rightEntities = nonSharedEntities.filter((n) => !leftEntities.includes(n));

        const placeSampleEntities = (entities: any[], originX: number, isLeft: boolean, fileNode: any) => {
          const count = entities.length;
          if (fileNode) {
            clusterLabels.push({
              key: fileNode.id,
              label: (fileNode.label || 'FILE').toUpperCase(),
              count: count + 1,
              x: originX,
              y: centerY - 150 * prox,
            });
          }
          if (count === 0) return;

          entities.forEach((node, idx) => {
            const startAngle = isLeft ? Math.PI / 2 : -Math.PI / 2;
            const angle = startAngle + ((idx + 0.5) / count) * Math.PI;
            const rad = (110 + (idx % 3) * 35) * prox;
            positions[node.id] = {
              x: originX + rad * Math.cos(angle),
              y: centerY + rad * Math.sin(angle),
            };
          });
        };

        placeSampleEntities(leftEntities, centerX - fileOffset, true, leftFile);
        placeSampleEntities(rightEntities, rightFile ? centerX + fileOffset : centerX, false, rightFile);
      } else {
        // Multi-sample (> 2 files): Each file is an anchor hub, with all artifacts clustering close around it!
        const numFiles = fileNodes.length;
        const fileRadius = Math.min(width * 0.36, Math.max(220 * prox, numFiles * 65 * prox));
        fileNodes.forEach((fn, fIdx) => {
          const fileAngle = (fIdx / numFiles) * 2 * Math.PI - Math.PI / 2;
          const fx = centerX + fileRadius * Math.cos(fileAngle);
          const fy = centerY + (fileRadius * 0.75) * Math.sin(fileAngle);
          positions[fn.id] = { x: fx, y: fy };

          const fileArtifacts = nonSharedEntities.filter((n) =>
            edges.some((e) => (e.source === fn.id && e.target === n.id) || (e.target === fn.id && e.source === n.id))
          );

          fileArtifacts.forEach((art, aIdx) => {
            const aAngle = fileAngle + ((aIdx - fileArtifacts.length / 2) / (fileArtifacts.length || 1)) * 1.5;
            const artDist = (65 + (aIdx % 3) * 28) * prox;
            positions[art.id] = {
              x: fx + artDist * Math.cos(aAngle),
              y: fy + artDist * Math.sin(aAngle),
            };
          });

          clusterLabels.push({
            key: fn.id,
            label: (fn.label || 'FILE').toUpperCase(),
            count: fileArtifacts.length + 1,
            x: fx,
            y: fy - Math.round(35 * prox) - 18,
          });
        });

        // Shared correlation entities in center nexus
        sharedEntities.forEach((node, idx) => {
          const angle = (idx / (sharedEntities.length || 1)) * 2 * Math.PI;
          positions[node.id] = {
            x: centerX + (90 * prox) * Math.cos(angle),
            y: centerY + (75 * prox) * Math.sin(angle),
          };
        });
      }
    } else if (layout === 'format') {
      // 4. GROUP BY FILE FORMAT (Groups files by Office, Exe, EVTX, PCAP, Archive, Email)
      const formatBuckets: Record<string, { label: string; nodes: any[] }> = {
        office: { label: 'OFFICE & MACROS', nodes: [] },
        executable: { label: 'BINARIES & PE', nodes: [] },
        log: { label: 'EVENT LOGS (EVTX)', nodes: [] },
        pcap: { label: 'NETWORK PCAPS', nodes: [] },
        archive: { label: 'ARCHIVES (ZIP)', nodes: [] },
        email: { label: 'EMAILS (MSG/EML)', nodes: [] },
        other: { label: 'OTHER ARTIFACTS', nodes: [] },
      };

      const getFileBucketKey = (node: any): string => {
        const fn = (node.label || node.id || '').toLowerCase();
        if (fn.endsWith('.docm') || fn.endsWith('.docx') || fn.endsWith('.doc') || fn.endsWith('.xls') || fn.endsWith('.xlsx')) return 'office';
        if (fn.endsWith('.exe') || fn.endsWith('.dll') || fn.endsWith('.bin') || fn.endsWith('.sys')) return 'executable';
        if (fn.endsWith('.evtx')) return 'log';
        if (fn.endsWith('.pcap') || fn.endsWith('.pcapng')) return 'pcap';
        if (fn.endsWith('.zip') || fn.endsWith('.7z') || fn.endsWith('.tar') || fn.endsWith('.gz')) return 'archive';
        if (fn.endsWith('.msg') || fn.endsWith('.eml')) return 'email';
        return 'other';
      };

      sortedNodes.forEach((n) => {
        if (n.type === 'file') {
          const bKey = getFileBucketKey(n);
          formatBuckets[bKey].nodes.push(n);
        } else {
          // Connect artifact to related file's format
          const connectedFile = sortedNodes.find(
            (fn) => fn.type === 'file' && edges.some((e) => (e.source === fn.id && e.target === n.id) || (e.target === fn.id && e.source === n.id))
          );
          if (connectedFile) {
            const bKey = getFileBucketKey(connectedFile);
            formatBuckets[bKey].nodes.push(n);
          } else {
            formatBuckets.other.nodes.push(n);
          }
        }
      });

      const activeBuckets = Object.entries(formatBuckets).filter(([_, b]) => b.nodes.length > 0);
      const bucketCount = activeBuckets.length;
      const bRadiusX = Math.min(width * 0.44, Math.max(300 * prox, bucketCount * 70 * prox));
      const bRadiusY = Math.min(height * 0.36, Math.max(160 * prox, bucketCount * 35 * prox));

      activeBuckets.forEach(([key, b], bIdx) => {
        const angle = (bIdx / (bucketCount || 1)) * 2 * Math.PI - Math.PI / 2;
        const bCenterX = centerX + bRadiusX * Math.cos(angle);
        const bCenterY = centerY + bRadiusY * Math.sin(angle);
        const nList = b.nodes;
        const subRad = Math.min(110 * prox, Math.max(50 * prox, nList.length * 15 * prox));

        nList.forEach((node, nIdx) => {
          if (nList.length === 1) {
            positions[node.id] = { x: bCenterX, y: bCenterY };
          } else {
            const subAngle = (nIdx / nList.length) * 2 * Math.PI;
            positions[node.id] = {
              x: bCenterX + subRad * Math.cos(subAngle),
              y: bCenterY + subRad * Math.sin(subAngle),
            };
          }
        });

        clusterLabels.push({
          key,
          label: b.label,
          count: nList.length,
          x: bCenterX,
          y: bCenterY - subRad - 18,
        });
      });
    } else if (layout === 'hierarchical') {
      // 5. HIERARCHICAL FORENSIC TIERS
      const tiers: any[][] = [[], [], [], []];
      sortedNodes.forEach((n) => {
        if (n.type === 'file') {
          tiers[0].push(n);
        } else if (['vulnerability', 'technique'].includes(n.type)) {
          tiers[1].push(n);
        } else if (['hash', 'timestamp', 'geolocation', 'ip', 'domain', 'url'].includes(n.type)) {
          tiers[2].push(n);
        } else {
          tiers[3].push(n);
        }
      });

      const tierY = [65 * prox, 185 * prox, 325 * prox, 475 * prox];
      tiers.forEach((tierNodes, tIdx) => {
        const count = tierNodes.length;
        if (count === 0) return;

        const baseSpacing = Math.min(220 * prox, Math.max(110 * prox, (width - 240) / (count || 1)));
        const totalSpan = (count - 1) * baseSpacing;
        const startX = centerX - totalSpan / 2;

        tierNodes.forEach((node, idx) => {
          positions[node.id] = {
            x: startX + idx * baseSpacing,
            y: tierY[tIdx],
          };
        });
      });
    } else if (layout === 'grid') {
      // 6. STRUCTURED GRID MATRIX
      const count = sortedNodes.length;
      const cols = Math.max(3, Math.min(6, Math.ceil(Math.sqrt(count * 1.1))));
      const rows = Math.ceil(count / cols);
      const cellW = Math.round(Math.min(240, Math.max(140, (width - 160) / cols)) * prox);
      const cellH = Math.round(Math.min(160, Math.max(100, (height - 130) / rows)) * prox);
      const startX = centerX - ((cols - 1) * cellW) / 2;
      const startY = centerY - ((rows - 1) * cellH) / 2;

      sortedNodes.forEach((node, idx) => {
        const c = idx % cols;
        const r = Math.floor(idx / cols);
        positions[node.id] = {
          x: startX + c * cellW,
          y: startY + r * cellH,
        };
      });
    }

    // 7. Overlap-Prevention & Collision Avoidance Relaxation Pass
    const minClearanceX = Math.round(115 * prox);
    const minClearanceY = Math.round(60 * prox);
    const nodeIds = Object.keys(positions);

    for (let iter = 0; iter < 12; iter++) {
      let maxOverlap = 0;
      for (let i = 0; i < nodeIds.length; i++) {
        const idA = nodeIds[i];
        const posA = positions[idA];
        for (let j = i + 1; j < nodeIds.length; j++) {
          const idB = nodeIds[j];
          const posB = positions[idB];

          const dx = posB.x - posA.x;
          const dy = posB.y - posA.y;

          const normX = dx / minClearanceX;
          const normY = dy / minClearanceY;
          const distSq = normX * normX + normY * normY;

          if (distSq < 1 && distSq > 0.0001) {
            const dist = Math.sqrt(distSq);
            const overlap = 1 - dist;
            if (overlap > maxOverlap) maxOverlap = overlap;

            const pushX = (normX / dist) * overlap * 0.5 * minClearanceX * 0.45;
            const pushY = (normY / dist) * overlap * 0.5 * minClearanceY * 0.45;

            posA.x -= pushX;
            posA.y -= pushY;
            posB.x += pushX;
            posB.y += pushY;
          } else if (distSq <= 0.0001) {
            posA.x -= 25;
            posB.x += 25;
          }
        }
      }
      if (maxOverlap < 0.02) break;
    }

    return { positions, clusterLabels };
  };

  const layoutGraphNodes = (nodes: any[], edges?: any[]) => {
    const { positions, clusterLabels } = calculateLayout(
      nodes,
      edges || [],
      layoutMode,
      sortMode,
      canvasSize.width,
      canvasSize.height,
      nodeProximity
    );
    setNodePositions(positions);
    setCategoryClusterLabels(clusterLabels);
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Cursor-centered smooth mouse scroll wheel & trackpad pinch-zoom (from EntityGraphCard)
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      let factor = 1.0;
      if (e.ctrlKey) {
        factor = Math.exp(-e.deltaY * 0.015);
      } else {
        factor = e.deltaY < 0 ? 1.12 : 0.89;
      }

      setGraphZoom((prevZoom) => {
        const nextZoom = Math.min(3.5, Math.max(0.3, prevZoom * factor));
        setGraphPan((prevPan) => {
          const nextPanX = mouseX - (mouseX - prevPan.x) * (nextZoom / prevZoom);
          const nextPanY = mouseY - (mouseY - prevPan.y) * (nextZoom / prevZoom);
          return { x: nextPanX, y: nextPanY };
        });
        return nextZoom;
      });
    };
    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, []);

  // Dynamically update canvas dimensions for responsive spacing
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const updateSize = () => {
      const rect = el.getBoundingClientRect();
      if (rect.width > 300 && rect.height > 300) {
        setCanvasSize((prev) => {
          if (Math.abs(prev.width - rect.width) > 20 || Math.abs(prev.height - rect.height) > 20) {
            return { width: Math.round(rect.width), height: Math.round(rect.height) };
          }
          return prev;
        });
      }
    };
    updateSize();
    const ro = new ResizeObserver(updateSize);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Category counts for filter badges
  const categoryCounts = useMemo(() => {
    const nodes = data?.campaign_graph?.nodes || [];
    return {
      total: nodes.length,
      shared: nodes.filter((n) => n.is_shared).length,
      hosts: nodes.filter((n) => n.type === 'host').length,
      hashes: nodes.filter((n) => n.type === 'hash').length,
      timestamps: nodes.filter((n) => n.type === 'timestamp').length,
      vulns: nodes.filter((n) => n.type === 'vulnerability').length,
      geo: nodes.filter((n) => n.type === 'geolocation').length,
      network: nodes.filter((n) => ['ip', 'domain', 'url'].includes(n.type)).length,
      identity: nodes.filter((n) => n.type === 'user').length,
      ttps: nodes.filter((n) => n.type === 'technique').length,
      artifacts: nodes.filter((n) => n.type === 'artifact').length,
    };
  }, [data]);

  // Filter options configuration
  const filterOptions = [
    { key: 'hosts', label: 'Hosts & Assets', count: categoryCounts.hosts, color: 'bg-green-600 text-white border-green-600', hoverColor: 'hover:bg-green-50 hover:text-green-700' },
    { key: 'hashes', label: 'Hashes', count: categoryCounts.hashes, color: 'bg-emerald-600 text-white border-emerald-600', hoverColor: 'hover:bg-emerald-50 hover:text-emerald-700' },
    { key: 'timestamps', label: 'Timestamps', count: categoryCounts.timestamps, color: 'bg-orange-600 text-white border-orange-600', hoverColor: 'hover:bg-orange-50 hover:text-orange-700' },
    { key: 'vulns', label: 'Vulnerabilities', count: categoryCounts.vulns, color: 'bg-rose-600 text-white border-rose-600', hoverColor: 'hover:bg-rose-50 hover:text-rose-700' },
    { key: 'geo', label: 'Geolocation', count: categoryCounts.geo, color: 'bg-cyan-600 text-white border-cyan-600', hoverColor: 'hover:bg-cyan-50 hover:text-cyan-700' },
    { key: 'network', label: 'IPs & Domains', count: categoryCounts.network, color: 'bg-sky-600 text-white border-sky-600', hoverColor: 'hover:bg-sky-50 hover:text-sky-700' },
    { key: 'identity', label: 'User Accounts', count: categoryCounts.identity, color: 'bg-amber-600 text-white border-amber-600', hoverColor: 'hover:bg-amber-50 hover:text-amber-700' },
    { key: 'ttps', label: 'ATT&CK TTPs', count: categoryCounts.ttps, color: 'bg-rose-700 text-white border-rose-700', hoverColor: 'hover:bg-rose-50 hover:text-rose-700' },
    { key: 'artifacts', label: 'Tools & APIs', count: categoryCounts.artifacts, color: 'bg-violet-600 text-white border-violet-600', hoverColor: 'hover:bg-violet-50 hover:text-violet-700' },
  ];

  const isAllSelected = useMemo(
    () => ALL_THREAT_FILTER_KEYS.length > 0 && ALL_THREAT_FILTER_KEYS.every((k) => selectedFilters.includes(k)),
    [ALL_THREAT_FILTER_KEYS, selectedFilters]
  );

  const handleToggleAllEntities = () => {
    if (isAllSelected) {
      setSelectedFilters([]);
    } else {
      setSelectedFilters([...ALL_THREAT_FILTER_KEYS]);
    }
  };

  const toggleFilter = (key: string) => {
    setSelectedFilters((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]
    );
  };

  const handleToggleSharedOnly = () => {
    setSharedOnlyFilter((prev) => {
      const next = !prev;
      if (next && selectedFilters.length === 0) {
        setSelectedFilters([...ALL_THREAT_FILTER_KEYS]);
      }
      return next;
    });
  };

  const handleResetFilters = () => {
    setSelectedFilters([...ALL_THREAT_FILTER_KEYS]);
    setSharedOnlyFilter(false);
  };

  const nodeDegreeMap = useMemo(() => {
    const map: Record<string, number> = {};
    if (!data?.campaign_graph?.edges) return map;
    data.campaign_graph.edges.forEach((e) => {
      map[e.source] = (map[e.source] || 0) + 1;
      map[e.target] = (map[e.target] || 0) + 1;
    });
    return map;
  }, [data]);

  // Multi-filtered graph nodes
  const filteredGraphNodes = useMemo(() => {
    if (!data?.campaign_graph?.nodes) return [];
    const nodes = data.campaign_graph.nodes;
    const edges = data.campaign_graph.edges || [];

    // Find all IDs of nodes that are shared across submitted files
    const sharedIds = new Set(nodes.filter((n) => n.is_shared).map((n) => n.id));

    // Find which file nodes connect to at least one shared node
    const fileIdsWithShared = new Set<string>();
    edges.forEach((e) => {
      if (sharedIds.has(e.source)) fileIdsWithShared.add(e.target);
      if (sharedIds.has(e.target)) fileIdsWithShared.add(e.source);
    });

    return nodes.filter((n) => {
      // Shared Only toggle constraint:
      // When active, strictly show only nodes that are shared between submitted files and the files that share them
      if (sharedOnlyFilter) {
        if (n.type === 'file') {
          if (!fileIdsWithShared.has(n.id)) return false;
        } else if (!n.is_shared) {
          return false;
        }
      }

      // Hide isolated/leaf nodes constraint (degree <= 1), keeping file hubs
      if (hideIsolatedNodes && n.type !== 'file' && (nodeDegreeMap[n.id] || 0) <= 1) {
        return false;
      }

      // Hide benign / low-severity informational entities
      if (hideBenignNodes && n.type !== 'file' && !n.is_shared && ['timestamp', 'user'].includes(n.type)) {
        return false;
      }

      // Base files are preserved as reference anchors (if not filtered out by sharedOnlyFilter)
      if (n.type === 'file') {
        return true;
      }

      // If no category filters are selected, non-file entities are filtered out
      if (selectedFilters.length === 0) {
        return false;
      }

      // Check if node matches ANY of the selected category filters
      return selectedFilters.some((f) => {
        if (f === 'hosts') return n.type === 'host';
        if (f === 'hashes') return n.type === 'hash';
        if (f === 'timestamps') return n.type === 'timestamp';
        if (f === 'vulns') return n.type === 'vulnerability';
        if (f === 'geo') return n.type === 'geolocation';
        if (f === 'network') return ['ip', 'domain', 'url'].includes(n.type);
        if (f === 'identity') return n.type === 'user';
        if (f === 'ttps') return n.type === 'technique';
        if (f === 'artifacts') return n.type === 'artifact';
        return false;
      });
    });
  }, [data, selectedFilters, sharedOnlyFilter, hideIsolatedNodes, hideBenignNodes, nodeDegreeMap]);

  const selectAllOfType = (typeKey: string) => {
    if (typeKey === 'all') {
      setSelectedNodeIds(new Set(filteredGraphNodes.map((n) => n.id)));
      return;
    }
    if (typeKey === 'none') {
      setSelectedNodeIds(new Set());
      setSelectedNode(null);
      return;
    }
    if (typeKey === 'shared') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => n.is_shared).map((n) => n.id)));
      return;
    }
    if (typeKey === 'file') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => n.type === 'file').map((n) => n.id)));
      return;
    }
    if (typeKey === 'hash') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => n.type === 'hash').map((n) => n.id)));
      return;
    }
    if (typeKey === 'network') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => ['ip', 'domain', 'url'].includes(n.type)).map((n) => n.id)));
      return;
    }
    if (typeKey === 'technique') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => n.type === 'technique').map((n) => n.id)));
      return;
    }
    if (typeKey === 'user') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => n.type === 'user').map((n) => n.id)));
      return;
    }
    if (typeKey === 'vulnerability') {
      setSelectedNodeIds(new Set(filteredGraphNodes.filter((n) => n.type === 'vulnerability').map((n) => n.id)));
      return;
    }
    if (typeKey === 'invert') {
      setSelectedNodeIds((prev) => {
        const next = new Set<string>();
        filteredGraphNodes.forEach((n) => {
          if (!prev.has(n.id)) next.add(n.id);
        });
        return next;
      });
    }
  };

  const visibleNodeIds = useMemo(() => new Set(filteredGraphNodes.map((n) => n.id)), [filteredGraphNodes]);

  // Edges filtered: ANY edge connected to a hidden/filtered node is hidden!
  const visibleEdges = useMemo(() => {
    if (!data?.campaign_graph?.edges) return [];
    return data.campaign_graph.edges.filter(
      (edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)
    );
  }, [data, visibleNodeIds]);

  // Re-layout & redraw graph automatically when visible nodes, edges, layout mode, sort mode, canvas size, or proximity changes
  useEffect(() => {
    if (filteredGraphNodes.length > 0) {
      const { positions, clusterLabels } = calculateLayout(
        filteredGraphNodes,
        visibleEdges,
        layoutMode,
        sortMode,
        canvasSize.width,
        canvasSize.height,
        nodeProximity
      );
      setNodePositions(positions);
      setCategoryClusterLabels(clusterLabels);
    } else {
      setNodePositions({});
      setCategoryClusterLabels([]);
    }
  }, [filteredGraphNodes, visibleEdges, layoutMode, sortMode, canvasSize, nodeProximity]);

  // Filtered Timeline Events
  const uniqueTimelineFiles = useMemo(() => {
    const list = data?.timeline_comparison?.events || [];
    return Array.from(new Set(list.map((e) => e.filename).filter(Boolean)));
  }, [data]);

  const uniqueTimelineHosts = useMemo(() => {
    const list = data?.timeline_comparison?.events || [];
    return Array.from(new Set(list.map((e) => e.computer).filter(Boolean)));
  }, [data]);

  const filteredTimelineEvents = useMemo(() => {
    let list = data?.timeline_comparison?.events || [];
    if (selectedTimelineFile !== 'all') {
      list = list.filter((e) => e.filename === selectedTimelineFile);
    }
    if (selectedTimelineHost !== 'all') {
      list = list.filter((e) => e.computer === selectedTimelineHost);
    }
    if (anomaliesOnly) {
      list = list.filter((e) => e.is_anomaly || e.is_timestomp);
    }
    if (timelineSearch.trim()) {
      const q = timelineSearch.toLowerCase();
      list = list.filter((e) =>
        (e.event && e.event.toLowerCase().includes(q)) ||
        (e.description && e.description.toLowerCase().includes(q)) ||
        (e.filename && e.filename.toLowerCase().includes(q)) ||
        (e.computer && e.computer.toLowerCase().includes(q)) ||
        (e.user && e.user.toLowerCase().includes(q)) ||
        (e.staging_phase && e.staging_phase.toLowerCase().includes(q))
      );
    }
    return list;
  }, [data, selectedTimelineFile, selectedTimelineHost, anomaliesOnly, timelineSearch]);

  // Export Timeline to CSV
  const handleExportTimeline = () => {
    const list = filteredTimelineEvents.length > 0 ? filteredTimelineEvents : (data?.timeline_comparison?.events || []);
    if (list.length === 0) return;
    const headers = ['Timestamp', 'File', 'Host', 'User', 'Category', 'Risk', 'Source', 'Event', 'Description', 'Anomaly', 'Phase'];
    const rows = list.map((e) => [
      `"${e.timestamp || ''}"`,
      `"${e.filename || ''}"`,
      `"${e.computer || ''}"`,
      `"${e.user || ''}"`,
      `"${e.category || ''}"`,
      `"${e.risk_level || ''}"`,
      `"${e.source || ''}"`,
      `"${e.event || ''}"`,
      `"${(e.description || '').replace(/"/g, '""')}"`,
      `"${e.is_anomaly ? 'YES' : 'NO'}"`,
      `"${e.staging_phase || ''}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_timeline_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="max-w-[96rem] mx-auto px-4 py-16 text-center">
        <div className="w-16 h-16 rounded-2xl bg-indigo-50 border border-indigo-100 flex items-center justify-center mx-auto mb-4 text-indigo-600 animate-pulse">
          <Network className="w-8 h-8 animate-spin" style={{ animationDuration: '6s' }} />
        </div>
        <h3 className="text-lg font-bold text-slate-900 mb-1">Synthesizing Incident Workspace Correlation</h3>
        <p className="text-xs font-mono text-slate-500">
          Cross-referencing IOCs, executing BinDiff structural matching, and rebuilding multi-sample timeline...
        </p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-[96rem] mx-auto px-4 py-16 text-center">
        <div className="w-16 h-16 rounded-2xl bg-rose-50 border border-rose-100 flex items-center justify-center mx-auto mb-4 text-rose-600">
          <AlertTriangle className="w-8 h-8" />
        </div>
        <h3 className="text-lg font-bold text-slate-900 mb-1">Correlation Engine Error</h3>
        <p className="text-sm text-slate-600 mb-4">{error || 'Could not correlate workspace samples.'}</p>
        <button
          onClick={() => fetchCorrelation()}
          className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg shadow-sm transition-colors cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry Correlation</span>
        </button>
      </div>
    );
  }

  const {
    campaign_summary,
    campaign_graph,
    binary_diff,
    timeline_comparison,
    hash_comparison,
    ioc_comparison,
    mitre_campaign,
    evtx_fleet_forensics,
  } = data;

  return (
    <div className="max-w-[96rem] mx-auto px-4 py-6 space-y-6">
      
      {/* 1. TOP HEADER & EXECUTIVE SUMMARY BANNER */}
      <div className="bg-white rounded-2xl p-6 text-slate-800 shadow-sm border border-slate-200">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200 flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-indigo-600" />
                Multi-Artifact Campaign Grouping
              </span>
              <span className="text-xs font-mono text-slate-500">
                Correlated Evidence: <strong className="text-slate-900">{data.total_jobs} Samples</strong>
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
              <Network className="w-7 h-7 text-indigo-600" />
              Incident Investigation & Relationship Mapping
            </h1>
            <p className="text-xs sm:text-sm text-slate-600 leading-relaxed font-sans">
              {campaign_summary.executive_narrative}
            </p>
          </div>

          {/* Quick Metrics Badges */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 shrink-0">
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 text-center">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Campaign Threat</div>
              <div className="text-base font-bold text-rose-600 mt-0.5 font-mono">{campaign_summary.overall_risk_level}</div>
            </div>
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 text-center">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Shared IOCs</div>
              <div className="text-base font-bold text-amber-600 mt-0.5 font-mono">{campaign_summary.shared_ioc_count}</div>
            </div>
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 text-center">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Unique IPs</div>
              <div className="text-base font-bold text-indigo-600 mt-0.5 font-mono">{campaign_summary.total_unique_ips}</div>
            </div>
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 text-center">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">ATT&CK TTPs</div>
              <div className="text-base font-bold text-purple-600 mt-0.5 font-mono">{campaign_summary.total_mitre_techniques}</div>
            </div>
          </div>
        </div>

        {/* Key Correlation Highlights */}
        {campaign_summary.key_correlations && campaign_summary.key_correlations.length > 0 && (
          <div className="mt-4 pt-4 border-t border-slate-200 flex flex-wrap gap-2">
            {campaign_summary.key_correlations.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono bg-amber-50 text-amber-900 border border-amber-200"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Interactive Cross-Artifact Reference Chain Banner */}
      {Boolean(data.cross_file_references && data.cross_file_references.total_references > 0) && (
        <div className="bg-gradient-to-r from-indigo-50 via-purple-50 to-blue-50 border border-indigo-200 rounded-2xl p-4 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 bg-indigo-600 text-white rounded-xl shadow-xs shrink-0 mt-0.5">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h4 className="font-bold text-xs text-indigo-950 uppercase tracking-wider">
                  Cross-Artifact Evidence Chain Active
                </h4>
                <span className="px-2 py-0.2 rounded-full text-[10px] font-bold bg-indigo-200 text-indigo-900 font-mono">
                  {data.cross_file_references?.total_references || 0} Intertwined Links
                </span>
              </div>
              <p className="text-xs text-indigo-900/80 mt-1 max-w-3xl leading-relaxed">
                Correlated evidence chain connects analyzed emails, dropper macros, C2 implants, endpoint event logs, network traffic, and exfiltration archives. Click any file tag below or navigate to the <strong>Cross-Artifact Links</strong> tab to inspect the complete chain.
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2.5">
                {jobs.map((j) => (
                  <button
                    key={j.jobId}
                    onClick={() => onSelectJob(j.jobId)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 bg-white hover:bg-indigo-600 text-indigo-900 hover:text-white border border-indigo-200 rounded-lg text-[11px] font-mono font-medium shadow-2xs transition-colors cursor-pointer"
                  >
                    <span>{j.filename}</span>
                    <ExternalLink className="w-3 h-3 opacity-60" />
                  </button>
                ))}
              </div>
            </div>
          </div>
          <button
            onClick={() => setActiveSubView('cross_refs')}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-bold font-sans shadow-xs transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer self-start md:self-center"
          >
            <span>Inspect Linked Chain</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 2. SUB-VIEW NAVIGATION TABS */}
      <div className="bg-white rounded-xl border border-slate-200 p-1.5 shadow-sm flex items-center gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveSubView('graph')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
            activeSubView === 'graph'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Network className="w-4 h-4" />
          <span>Threat Graph ({campaign_graph.total_nodes} nodes)</span>
        </button>

        <button
          onClick={() => setActiveSubView('bindiff')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
            activeSubView === 'bindiff'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <GitCompare className="w-4 h-4" />
          <span>BinDiff (Binary Diff)</span>
          {binary_diff.available && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-white/20 text-white">
              {binary_diff.binary_count} binaries
            </span>
          )}
        </button>

        {data.evtx_fleet_forensics?.available && (
          <button
            onClick={() => setActiveSubView('evtx_fleet')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
              activeSubView === 'evtx_fleet'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Server className="w-4 h-4" />
            <span>Fleet EVTX Forensics</span>
            <span
              className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                activeSubView === 'evtx_fleet'
                  ? 'bg-white/20 text-white'
                  : 'bg-indigo-50 text-indigo-700 border border-indigo-200'
              }`}
            >
              {data.evtx_fleet_forensics.total_hosts} host{data.evtx_fleet_forensics.total_hosts === 1 ? '' : 's'}
            </span>
          </button>
        )}

        {data.pcap_fleet_intelligence?.available && (
          <button
            onClick={() => setActiveSubView('pcap_fleet')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 cursor-pointer ${
              activeSubView === 'pcap_fleet'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Radio className="w-4 h-4" />
            <span>Fleet PCAP Network</span>
            <span
              className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                activeSubView === 'pcap_fleet'
                  ? 'bg-white/20 text-white'
                  : 'bg-indigo-50 text-indigo-700 border border-indigo-200'
              }`}
            >
              {data.pcap_fleet_intelligence.total_captures} sensor{data.pcap_fleet_intelligence.total_captures === 1 ? '' : 's'}
            </span>
          </button>
        )}

        <button
          onClick={() => setActiveSubView('timeline')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 cursor-pointer ${
            activeSubView === 'timeline'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Clock className="w-4 h-4" />
          <span>Unified Timeline ({timeline_comparison.total_events})</span>
          {evtxJobs.length >= 2 && (
            <span
              className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                activeSubView === 'timeline'
                  ? 'bg-white/20 text-white'
                  : 'bg-indigo-50 text-indigo-700 border border-indigo-200'
              }`}
            >
              {evtxJobs.length} EVTX Swimlanes
            </span>
          )}
          {timeline_comparison.timestomp_detected && (
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
          )}
        </button>

        <button
          onClick={() => setActiveSubView('hashes')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
            activeSubView === 'hashes'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Hash className="w-4 h-4" />
          <span>Hashes & Similarity</span>
        </button>

        <button
          onClick={() => setActiveSubView('infrastructure')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
            activeSubView === 'infrastructure'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Infrastructure & Geolocation</span>
        </button>

        <button
          onClick={() => setActiveSubView('mitre')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
            activeSubView === 'mitre'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Campaign ATT&CK Matrix</span>
        </button>

        {Boolean(data.cross_file_references && data.cross_file_references.total_references > 0) && (
          <button
            onClick={() => setActiveSubView('cross_refs')}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 cursor-pointer ${
              activeSubView === 'cross_refs'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200/60'
            }`}
          >
            <Sparkles className="w-4 h-4 text-amber-500" />
            <span>Cross-Artifact Links</span>
            <span
              className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                activeSubView === 'cross_refs'
                  ? 'bg-white/20 text-white'
                  : 'bg-indigo-200/80 text-indigo-950'
              }`}
            >
              {data.cross_file_references?.total_references}
            </span>
          </button>
        )}
      </div>

      {/* 3. TAB VIEW CONTENT */}

      {/* VIEW A: THREAT GRAPH */}
      {activeSubView === 'graph' && (
        <div className="bg-white rounded-3xl border border-slate-200 shadow-sm overflow-hidden relative min-h-[690px] flex flex-col transition-all">
          {/* Graph Controls Toolbar */}
          <div className="p-4 bg-slate-50/80 border-b border-slate-200/80 flex flex-col gap-3 z-10">
            {/* Row 1: Filter Pills (Multi-Select) */}
            <div id="threat-graph-filter-bar" className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mr-1 hidden lg:inline">Filters:</span>
                <button
                  onClick={handleToggleAllEntities}
                  data-filter="all"
                  title={isAllSelected ? "Click to deselect all filters" : "Click to select all filters"}
                  className={`px-3 py-1 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1 ${
                    isAllSelected
                      ? 'bg-slate-900 text-white shadow-2xs font-semibold border border-slate-900'
                      : 'bg-slate-100 text-slate-400 border border-slate-200 hover:bg-slate-200/70 hover:text-slate-600'
                  }`}
                >
                  {isAllSelected && <Check className="w-3 h-3 stroke-[2.5]" />}
                  <span>All Entities</span>
                  <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${isAllSelected ? 'bg-white/20 text-white' : 'bg-slate-200 text-slate-400'}`}>
                    {categoryCounts.total}
                  </span>
                </button>
                <button
                  onClick={handleToggleSharedOnly}
                  data-filter="shared_only"
                  title="Only show artifacts and files shared across submitted samples"
                  className={`px-3 py-1 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
                    sharedOnlyFilter
                      ? 'bg-indigo-600 text-white shadow-2xs font-semibold border border-indigo-600'
                      : 'text-slate-600 hover:bg-indigo-50 hover:text-indigo-700 bg-white border border-slate-200'
                  }`}
                >
                  {sharedOnlyFilter && <Check className="w-3 h-3 stroke-[2.5]" />}
                  <span>Shared Only</span>
                  <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${sharedOnlyFilter ? 'bg-indigo-700/60 text-white' : 'bg-slate-100 text-slate-600'}`}>
                    {categoryCounts.shared}
                  </span>
                </button>
                {filterOptions.map((opt) => {
                  const isSelected = selectedFilters.includes(opt.key);
                  return (
                    <button
                      key={opt.key}
                      onClick={() => toggleFilter(opt.key)}
                      data-filter={opt.key}
                      className={`px-3 py-1 rounded-xl text-xs font-semibold transition-all cursor-pointer flex items-center gap-1 ${
                        isSelected
                          ? `${opt.color} shadow-2xs font-semibold`
                          : `text-slate-600 ${opt.hoverColor} bg-white border border-slate-200`
                      }`}
                    >
                      {isSelected && <Check className="w-3 h-3 stroke-[2.5]" />}
                      <span>{opt.label}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${isSelected ? 'bg-black/20 text-white' : 'bg-slate-100 text-slate-600'}`}>
                        {opt.count}
                      </span>
                    </button>
                  );
                })}
              </div>

              {(!isAllSelected || sharedOnlyFilter) && (
                <button
                  onClick={handleResetFilters}
                  className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 underline underline-offset-2 cursor-pointer transition-colors ml-auto"
                >
                  Reset filters
                </button>
              )}
            </div>

            {/* Row 2: Layout / Grouping, Sorting, Spacing, and Visibility Controls */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-slate-200/60">
              <div className="flex items-center gap-2.5 flex-wrap">
                {/* Grouping & Layout Selector */}
                <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 shadow-2xs">
                  <Layers className="w-3.5 h-3.5 text-indigo-500" />
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Group/Layout:</span>
                  <select
                    id="threat-graph-layout-select"
                    value={layoutMode}
                    onChange={(e) => setLayoutMode(e.target.value as any)}
                    className="bg-transparent font-medium text-slate-800 text-xs focus:outline-none cursor-pointer pr-1"
                  >
                    <option value="sample">Group by Analyzed File (Artifact Hubs)</option>
                    <option value="category">Group by Entity Type</option>
                    <option value="format">Group by File Format</option>
                    <option value="radial">Radial Orbit</option>
                    <option value="hierarchical">Hierarchical Tiers</option>
                    <option value="grid">Structured Grid</option>
                  </select>
                </div>

                {/* Sorting Mode Selector */}
                <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 shadow-2xs">
                  <ArrowUpDown className="w-3.5 h-3.5 text-indigo-500" />
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Sort:</span>
                  <select
                    id="threat-graph-sort-select"
                    value={sortMode}
                    onChange={(e) => setSortMode(e.target.value as any)}
                    className="bg-transparent font-medium text-slate-800 text-xs focus:outline-none cursor-pointer pr-1"
                  >
                    <option value="connectivity">Connectivity (Degree)</option>
                    <option value="threat_severity">Threat Severity & Risk</option>
                    <option value="shared_first">Shared Entities First</option>
                    <option value="alpha">Alphabetical (A-Z)</option>
                    <option value="reverse_alpha">Alphabetical (Z-A)</option>
                    <option value="type">Entity Category</option>
                  </select>
                </div>

                {/* Spacing / Proximity Selector */}
                <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 shadow-2xs">
                  <SlidersHorizontal className="w-3.5 h-3.5 text-indigo-500" />
                  <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Proximity:</span>
                  <select
                    id="threat-graph-proximity-select"
                    value={nodeProximity}
                    onChange={(e) => setNodeProximity(e.target.value as any)}
                    className="bg-transparent font-medium text-slate-800 text-xs focus:outline-none cursor-pointer pr-1"
                  >
                    <option value="close">Close (0.65x)</option>
                    <option value="middle">Middle (1.0x)</option>
                    <option value="far">Far (1.6x)</option>
                    <option value="very_far">Very Far (2.4x)</option>
                  </select>
                </div>

                {/* Hide Controls */}
                <div className="flex items-center gap-1 bg-white border border-slate-200 rounded-xl p-0.5 shadow-2xs">
                  <button
                    type="button"
                    id="threat-graph-hide-isolated-btn"
                    onClick={() => setHideIsolatedNodes((prev) => !prev)}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                      hideIsolatedNodes
                        ? 'bg-amber-500 text-white shadow-2xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                    title="Hide single-connection leaf nodes to reduce clutter"
                  >
                    {hideIsolatedNodes ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5 text-slate-400" />}
                    <span>Hide Leaves</span>
                  </button>

                  <button
                    type="button"
                    id="threat-graph-hide-benign-btn"
                    onClick={() => setHideBenignNodes((prev) => !prev)}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                      hideBenignNodes
                        ? 'bg-amber-500 text-white shadow-2xs'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                    title="Hide benign timestamps & low-severity informational entities"
                  >
                    {hideBenignNodes ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5 text-slate-400" />}
                    <span>Hide Benign</span>
                  </button>
                </div>

                {/* Live Stats */}
                <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-slate-100/90 text-[11px] font-medium text-slate-600 border border-slate-200 font-mono">
                  <span><strong className="text-slate-900">{filteredGraphNodes.length}</strong> / {data.campaign_graph.nodes.length} nodes</span>
                  <span className="text-slate-300">•</span>
                  <span><strong className="text-slate-900">{visibleEdges.length}</strong> lines</span>
                </div>
              </div>

              {/* Drag Hint & Zoom / Pan Controls */}
              <div className="flex items-center gap-2">
                <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-slate-100/90 text-[11px] font-medium text-slate-500 border border-slate-200">
                  <Move className="w-3.5 h-3.5 text-slate-400" />
                  <span>Drag node(s) to move</span>
                </div>

                <div className="flex items-center gap-1 bg-white border border-slate-200 rounded-xl p-1 shadow-2xs">
                  <button
                    onClick={() => setGraphZoom((z) => Math.min(3.5, z + 0.2))}
                    className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
                    title="Zoom In"
                  >
                    <ZoomIn className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setGraphZoom((z) => Math.max(0.3, z - 0.2))}
                    className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
                    title="Zoom Out"
                  >
                    <ZoomOut className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => {
                      setGraphZoom(1);
                      setGraphPan({ x: 0, y: 0 });
                      setSelectedNode(null);
                      setSelectedNodeIds(new Set());
                      if (filteredGraphNodes.length > 0) {
                        const { positions, clusterLabels } = calculateLayout(
                          filteredGraphNodes,
                          visibleEdges,
                          layoutMode,
                          sortMode,
                          canvasSize.width,
                          canvasSize.height,
                          nodeProximity
                        );
                        setNodePositions(positions);
                        setCategoryClusterLabels(clusterLabels);
                      }
                    }}
                    className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
                    title="Reset View & Layout"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            {/* Row 3: Quick Select All by Type & Group Movement Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-2.5 pt-2.5 border-t border-slate-200/60 text-xs">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mr-1 flex items-center gap-1">
                  <CheckSquare className="w-3.5 h-3.5 text-indigo-500" />
                  <span>Select Group:</span>
                </span>

                <button
                  type="button"
                  onClick={() => selectAllOfType('file')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-indigo-50 text-indigo-700 border border-slate-200 hover:border-indigo-300 transition-colors cursor-pointer shadow-2xs"
                >
                  Files
                </button>
                <button
                  type="button"
                  onClick={() => selectAllOfType('hash')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-emerald-50 text-emerald-700 border border-slate-200 hover:border-emerald-300 transition-colors cursor-pointer shadow-2xs"
                >
                  Hashes
                </button>
                <button
                  type="button"
                  onClick={() => selectAllOfType('network')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-sky-50 text-sky-700 border border-slate-200 hover:border-sky-300 transition-colors cursor-pointer shadow-2xs"
                >
                  IPs & URLs
                </button>
                <button
                  type="button"
                  onClick={() => selectAllOfType('technique')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-rose-50 text-rose-700 border border-slate-200 hover:border-rose-300 transition-colors cursor-pointer shadow-2xs"
                >
                  ATT&CK TTPs
                </button>
                <button
                  type="button"
                  onClick={() => selectAllOfType('user')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-amber-50 text-amber-700 border border-slate-200 hover:border-amber-300 transition-colors cursor-pointer shadow-2xs"
                >
                  Users
                </button>
                <button
                  type="button"
                  onClick={() => selectAllOfType('shared')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-purple-50 text-purple-700 border border-slate-200 hover:border-purple-300 transition-colors cursor-pointer shadow-2xs"
                >
                  Shared
                </button>
                <button
                  type="button"
                  onClick={() => selectAllOfType('all')}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 transition-colors cursor-pointer"
                >
                  Select All
                </button>
                {selectedNodeIds.size > 0 && (
                  <button
                    type="button"
                    onClick={() => selectAllOfType('none')}
                    className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-rose-50 text-rose-600 border border-rose-200 transition-colors cursor-pointer"
                  >
                    Deselect
                  </button>
                )}
              </div>

              {selectedNodeIds.size > 0 && (
                <div className="flex items-center gap-2 bg-indigo-50 border border-indigo-200 text-indigo-900 px-3 py-1 rounded-xl text-xs font-medium">
                  <Move className="w-3.5 h-3.5 text-indigo-600 animate-pulse" />
                  <span>
                    <strong>{selectedNodeIds.size}</strong> nodes selected — drag any selected node to move the group
                  </span>
                  <button
                    type="button"
                    onClick={() => selectAllOfType('none')}
                    className="ml-1 text-[11px] text-indigo-700 hover:text-indigo-950 font-bold underline cursor-pointer"
                  >
                    Clear
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Main SVG Visualization Canvas (matching EntityGraphCard graphics) */}
          <div
            className="flex-1 relative cursor-grab active:cursor-grabbing select-none overflow-hidden bg-slate-50/70"
            onMouseDown={handleCanvasMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            <svg
              ref={svgRef}
              id="threat-graph-canvas"
              className="w-full h-[650px]"
              onClick={(e) => {
                if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).id === 'threat-graph-canvas-bg') {
                  setSelectedNode(null);
                  setSelectedNodeIds(new Set());
                }
              }}
            >
              <defs>
                {/* Arrowhead Markers */}
                <marker id="threat-arrow-slate" markerWidth="9" markerHeight="6" refX="17" refY="3" orient="auto">
                  <polygon points="0 0, 9 3, 0 6" fill="#94a3b8" />
                </marker>
                <marker id="threat-arrow-danger" markerWidth="9" markerHeight="6" refX="17" refY="3" orient="auto">
                  <polygon points="0 0, 9 3, 0 6" fill="#f43f5e" />
                </marker>
                <marker id="threat-arrow-indigo" markerWidth="9" markerHeight="6" refX="17" refY="3" orient="auto">
                  <polygon points="0 0, 9 3, 0 6" fill="#6366f1" />
                </marker>
                <marker id="threat-arrow-purple" markerWidth="9" markerHeight="6" refX="17" refY="3" orient="auto">
                  <polygon points="0 0, 9 3, 0 6" fill="#a855f7" />
                </marker>

                {/* Subtle Dot Matrix Pattern */}
                <pattern id="threat-light-dot-grid" width="24" height="24" patternUnits="userSpaceOnUse">
                  <circle cx="2" cy="2" r="1.2" fill="#cbd5e1" opacity="0.65" />
                </pattern>
              </defs>

              {/* Dot Matrix Background */}
              <rect id="threat-graph-canvas-bg" width="100%" height="100%" fill="url(#threat-light-dot-grid)" />

              {/* Content Group with Zoom/Pan */}
              <g transform={`translate(${graphPan.x}, ${graphPan.y}) scale(${graphZoom})`}>
                {/* Visual Layout Guides / Category & Tier Headers */}
                {layoutMode === 'category' && (
                  <g className="select-none pointer-events-none">
                    {categoryClusterLabels.map((cl) => {
                      const pillWidth = Math.max(70, cl.label.length * 6.5 + 24);
                      return (
                        <g key={cl.key} transform={`translate(${cl.x}, ${cl.y})`}>
                          <rect
                            x={-pillWidth / 2}
                            y="-9"
                            width={pillWidth}
                            height="18"
                            rx="9"
                            fill="#ffffff"
                            stroke="#cbd5e1"
                            strokeWidth="1"
                            opacity="0.95"
                          />
                          <text
                            y="3.5"
                            textAnchor="middle"
                            fill="#475569"
                            fontSize="8.5px"
                            fontWeight="700"
                            fontFamily="ui-sans-serif, system-ui, sans-serif"
                          >
                            {cl.label} ({cl.count})
                          </text>
                        </g>
                      );
                    })}
                  </g>
                )}

                {layoutMode === 'hierarchical' && (
                  <g className="select-none pointer-events-none opacity-50">
                    <line x1="20" y1="125" x2={canvasSize.width - 20} y2="125" stroke="#cbd5e1" strokeDasharray="3 3" />
                    <line x1="20" y1="255" x2={canvasSize.width - 20} y2="255" stroke="#cbd5e1" strokeDasharray="3 3" />
                    <line x1="20" y1="400" x2={canvasSize.width - 20} y2="400" stroke="#cbd5e1" strokeDasharray="3 3" />
                    <text x="30" y="55" fill="#6366f1" fontSize="9px" fontWeight="bold" fontFamily="monospace">TIER 0: FILE SAMPLES</text>
                    <text x="30" y="165" fill="#e11d48" fontSize="9px" fontWeight="bold" fontFamily="monospace">TIER 1: VULNERABILITIES & TECHNIQUES</text>
                    <text x="30" y="305" fill="#0ea5e9" fontSize="9px" fontWeight="bold" fontFamily="monospace">TIER 2: FORENSIC METADATA & NETWORK</text>
                    <text x="30" y="450" fill="#64748b" fontSize="9px" fontWeight="bold" fontFamily="monospace">TIER 3: IDENTITIES & TOOLS</text>
                  </g>
                )}

                {layoutMode === 'sample' && (
                  <g className="select-none pointer-events-none opacity-50">
                    <line x1={canvasSize.width / 2 - 160} y1="30" x2={canvasSize.width / 2 - 160} y2={canvasSize.height - 30} stroke="#cbd5e1" strokeDasharray="3 3" />
                    <line x1={canvasSize.width / 2 + 160} y1="30" x2={canvasSize.width / 2 + 160} y2={canvasSize.height - 30} stroke="#cbd5e1" strokeDasharray="3 3" />
                    <text x={canvasSize.width / 2 - 350} y="45" fill="#6366f1" fontSize="9px" fontWeight="bold" fontFamily="monospace" textAnchor="middle">SAMPLE A ARTIFACTS</text>
                    <text x={canvasSize.width / 2} y="45" fill="#6366f1" fontSize="9px" fontWeight="bold" fontFamily="monospace" textAnchor="middle">SHARED ARTIFACTS</text>
                    <text x={canvasSize.width / 2 + 350} y="45" fill="#6366f1" fontSize="9px" fontWeight="bold" fontFamily="monospace" textAnchor="middle">SAMPLE B ARTIFACTS</text>
                  </g>
                )}

                {/* Edges: only between visible nodes */}
                {visibleEdges.map((edge, idx) => {
                  const srcPos = nodePositions[edge.source];
                  const dstPos = nodePositions[edge.target];
                  if (!srcPos || !dstPos) return null;

                  const isSharedEdge = edge.is_shared;
                  const isThreat = edge.type === 'contains' || edge.type === 'threat';
                  const midX = (srcPos.x + dstPos.x) / 2;
                  const midY = (srcPos.y + dstPos.y) / 2;

                  let strokeColor = '#94a3b8';
                  let strokeWidth = 1.2;
                  let markerUrl = 'url(#threat-arrow-slate)';

                  if (isThreat) {
                    strokeColor = '#f43f5e';
                    strokeWidth = 1.8;
                    markerUrl = 'url(#threat-arrow-danger)';
                  } else if (isSharedEdge) {
                    strokeColor = '#6366f1';
                    strokeWidth = 1.8;
                    markerUrl = 'url(#threat-arrow-indigo)';
                  } else if (edge.source.startsWith('file') || edge.target.startsWith('file') || edge.source.startsWith('job_root') || edge.target.startsWith('job_root')) {
                    strokeColor = '#818cf8';
                    strokeWidth = 1.4;
                    markerUrl = 'url(#threat-arrow-indigo)';
                  }

                  const edgeLabel = edge.label || (edge.is_shared ? 'Shared' : '');

                  return (
                    <g key={`edge-${idx}`}>
                      <line
                        x1={srcPos.x}
                        y1={srcPos.y}
                        x2={dstPos.x}
                        y2={dstPos.y}
                        stroke={strokeColor}
                        strokeWidth={strokeWidth}
                        strokeDasharray={isSharedEdge ? '4 2' : 'none'}
                        markerEnd={markerUrl}
                        opacity="0.85"
                      />
                      {edgeLabel && (
                        <g transform={`translate(${midX}, ${midY})`}>
                          <rect
                            x="-36"
                            y="-8"
                            width="72"
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
                            {edgeLabel.length > 13 ? edgeLabel.substring(0, 12) + '..' : edgeLabel}
                          </text>
                        </g>
                      )}
                    </g>
                  );
                })}

                {/* Nodes with Dragging & EntityGraphCard Styling */}
                {filteredGraphNodes.map((node) => {
                  const pos = nodePositions[node.id];
                  if (!pos) return null;

                  const isFile = node.type === 'file';
                  const isShared = node.is_shared;
                  const isSelected = selectedNode?.id === node.id;
                  const styling = getNodeStyling(node);
                  const nodeRadius = isFile ? 24 : 16;

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (!hasDraggedNodeRef.current) {
                          setSelectedNode(node);
                        }
                      }}
                      className="cursor-move group"
                    >
                      {/* Shared Tag Badge Above Node */}
                      {isShared && (
                        <g transform={`translate(0, -${nodeRadius + 9})`} className="pointer-events-none select-none">
                          <rect
                            x="-22"
                            y="-6"
                            width="44"
                            height="13"
                            rx="6.5"
                            fill="#ffffff"
                            stroke="#6366f1"
                            strokeWidth="1.2"
                            className="filter drop-shadow-2xs"
                          />
                          <text
                            y="3"
                            textAnchor="middle"
                            fill="#4f46e5"
                            fontSize="7.5px"
                            fontWeight="bold"
                            fontFamily="ui-sans-serif, system-ui, sans-serif"
                            letterSpacing="0.05em"
                          >
                            SHARED
                          </text>
                        </g>
                      )}

                      {/* Selection Halo / Ring (Single Selected or Multi-Selected) */}
                      {(isSelected || selectedNodeIds.has(node.id)) && (
                        <circle
                          r={nodeRadius + (selectedNodeIds.has(node.id) ? 6 : 4)}
                          fill={selectedNodeIds.has(node.id) ? '#6366f1' : 'none'}
                          fillOpacity={selectedNodeIds.has(node.id) ? 0.15 : 0}
                          stroke="#4f46e5"
                          strokeWidth="2.5"
                          strokeDasharray={selectedNodeIds.has(node.id) && selectedNodeIds.size > 1 ? '4 2' : undefined}
                          className={selectedNodeIds.has(node.id) && selectedNodeIds.size > 1 ? 'animate-pulse' : ''}
                        />
                      )}

                      {/* Main Node Circle */}
                      <circle
                        r={nodeRadius}
                        fill={styling.fill}
                        stroke={styling.stroke}
                        strokeWidth="2"
                        className="transition-transform group-hover:scale-110 shadow-xs"
                      />

                      {/* Inner Node Text / Icon Abbreviation */}
                      <text
                        y="3.5"
                        textAnchor="middle"
                        fill={styling.text}
                        fontSize={isFile ? '10px' : '8.5px'}
                        fontWeight="bold"
                        fontFamily="ui-sans-serif, system-ui, sans-serif"
                        className="select-none pointer-events-none"
                      >
                        {isFile
                          ? 'FILE'
                          : node.type === 'host'
                          ? 'HOST'
                          : node.type === 'hash'
                          ? 'HASH'
                          : node.type === 'timestamp'
                          ? 'TIME'
                          : node.type === 'vulnerability'
                          ? 'VULN'
                          : node.type === 'geolocation'
                          ? 'GEO'
                          : node.type === 'ip'
                          ? 'IP'
                          : node.type === 'domain'
                          ? 'DOM'
                          : node.type === 'url'
                          ? 'URL'
                          : node.type === 'user'
                          ? 'USER'
                          : node.type === 'technique'
                          ? 'TTP'
                          : node.type === 'artifact'
                          ? 'TOOL'
                          : node.type.substring(0, 3).toUpperCase()}
                      </text>

                      {/* Node Label Text */}
                      <g transform={`translate(0, ${nodeRadius + 14})`}>
                        <rect
                          x={-Math.min(node.label.length * 3.4, 58)}
                          y="-8"
                          width={Math.min(node.label.length * 6.8, 116)}
                          height="15"
                          rx="4"
                          fill="#ffffff"
                          stroke="#cbd5e1"
                          strokeWidth="0.8"
                          opacity="0.95"
                        />
                        <text
                          y="2.5"
                          textAnchor="middle"
                          fill="#0f172a"
                          fontSize="9px"
                          fontWeight={isFile ? 'bold' : '600'}
                          fontFamily="ui-monospace, monospace"
                          className="select-none pointer-events-none"
                        >
                          {node.label.length > 18 ? node.label.substring(0, 17) + '…' : node.label}
                        </text>
                      </g>
                    </g>
                  );
                })}
              </g>
            </svg>

            {/* Side Inspection Drawer on Node Click */}
            {selectedNode && (
              <div className="absolute right-4 top-4 bottom-4 w-84 bg-white/95 backdrop-blur-md rounded-2xl border border-slate-200 p-5 text-slate-800 shadow-xl flex flex-col z-20 transition-all">
                <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-indigo-600 font-bold">
                      Entity Inspector
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-mono uppercase font-bold border ${getNodeStyling(selectedNode).badge}`}>
                      {selectedNode.type}
                    </span>
                    {selectedNode.is_shared && (
                      <span className="px-2 py-0.5 rounded text-[9px] font-mono uppercase font-bold bg-indigo-50 text-indigo-700 border border-indigo-200 flex items-center gap-1">
                        <Link2 className="w-3 h-3" />
                        <span>SHARED</span>
                      </span>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedNode(null)}
                    className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                  >
                    ×
                  </button>
                </div>

                <div className="py-4 space-y-4 flex-1 overflow-y-auto">
                  {/* Entity Full Label & Copy */}
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase font-semibold">Entity Value</span>
                    <div className="flex items-center justify-between gap-2 mt-1 bg-slate-50 p-2.5 rounded-xl border border-slate-200">
                      <div className="text-xs font-bold font-mono text-slate-900 break-all">
                        {selectedNode.full_label || selectedNode.label}
                      </div>
                      <button
                        onClick={() => handleCopy(selectedNode.full_label || selectedNode.label, 'label')}
                        className="p-1 rounded text-slate-400 hover:text-indigo-600 shrink-0"
                        title="Copy to clipboard"
                      >
                        {copiedKey === 'label' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Shared Indicator */}
                  {selectedNode.is_shared && (
                    <div className="p-2.5 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center gap-2 text-xs text-indigo-900">
                      <Sparkles className="w-4 h-4 text-indigo-600 shrink-0" />
                      <div>
                        <strong className="block font-semibold">Shared Campaign Artifact</strong>
                        <span className="text-[11px] text-indigo-700">Observed across multiple submitted files</span>
                      </div>
                    </div>
                  )}

                  {/* Forensic Metadata */}
                  {selectedNode.details && (
                    <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 text-xs font-mono space-y-2 text-slate-700">
                      <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">Forensic Attributes</div>

                      {/* Hash Details */}
                      {selectedNode.details.hash_value && (
                        <div>
                          <div className="flex justify-between items-center mb-1">
                            <span className="text-slate-500 font-bold">{selectedNode.details.hash_type || 'Hash Digest'}:</span>
                            <button
                              onClick={() => handleCopy(selectedNode.details.hash_value, 'hash_val')}
                              className="text-[10px] text-indigo-600 hover:text-indigo-800 flex items-center gap-1 font-bold"
                            >
                              {copiedKey === 'hash_val' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === 'hash_val' ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <div className="p-2 rounded bg-white border border-slate-200 text-[10px] font-mono break-all text-slate-800 font-semibold select-all">
                            {selectedNode.details.hash_value}
                          </div>
                        </div>
                      )}

                      {/* Timestamp Details */}
                      {selectedNode.details.timestamp && (
                        <div className="space-y-1">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Timestamp:</span>
                            <span className="font-semibold text-slate-800">{selectedNode.details.timestamp}</span>
                          </div>
                          {selectedNode.details.source && (
                            <div className="flex justify-between">
                              <span className="text-slate-500">Source:</span>
                              <span className="text-slate-700">{selectedNode.details.source}</span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Vulnerability Details */}
                      {selectedNode.details.cve && (
                        <div className="space-y-1">
                          <div className="flex justify-between">
                            <span className="text-slate-500">CVE ID:</span>
                            <span className="font-bold text-rose-700">{selectedNode.details.cve}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Threat Level:</span>
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-rose-100 text-rose-800 uppercase">Critical</span>
                          </div>
                        </div>
                      )}

                      {selectedNode.details.rule_name && (
                        <div className="space-y-1">
                          <div className="flex justify-between">
                            <span className="text-slate-500">YARA Rule:</span>
                            <span className="font-semibold text-rose-700">{selectedNode.details.rule_name}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Engine:</span>
                            <span className="text-slate-700">YARA Static Engine</span>
                          </div>
                        </div>
                      )}

                      {selectedNode.details.signature && (
                        <div className="space-y-1">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Verdict:</span>
                            <span className="font-bold text-rose-700">{selectedNode.details.signature}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Scanner:</span>
                            <span className="text-slate-700">{selectedNode.details.engine || 'Antivirus'}</span>
                          </div>
                        </div>
                      )}

                      {/* Toolchain / API Details */}
                      {selectedNode.details.tool_name && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Toolchain:</span>
                          <span className="font-semibold text-slate-800">{selectedNode.details.tool_name}</span>
                        </div>
                      )}

                      {selectedNode.details.api && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">API Capability:</span>
                          <span className="font-semibold text-amber-800">{selectedNode.details.api}</span>
                        </div>
                      )}

                      {selectedNode.details.signer && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Signer:</span>
                          <span className="font-semibold text-slate-800">{selectedNode.details.signer}</span>
                        </div>
                      )}

                      {/* Location & ASN Details */}
                      {selectedNode.details.country && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Location:</span>
                          <span className="font-semibold text-slate-800">{selectedNode.details.country}{selectedNode.details.city ? `, ${selectedNode.details.city}` : ''}</span>
                        </div>
                      )}
                      {selectedNode.details.asn && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">ASN:</span>
                          <span className="font-semibold text-slate-800">{selectedNode.details.asn}</span>
                        </div>
                      )}
                      {selectedNode.details.seen_in_files && (
                        <div className="pt-2 border-t border-slate-200">
                          <span className="text-slate-500 block mb-1.5 font-bold">
                            Correlated Samples ({selectedNode.details.seen_in_files.length}):
                          </span>
                          <ul className="space-y-1.5">
                            {selectedNode.details.seen_in_files.map((f: any, idx: number) => (
                              <li key={idx} className="flex items-center justify-between bg-white border border-slate-200 px-2.5 py-1.5 rounded-lg shadow-2xs">
                                <span className="truncate max-w-[150px] text-slate-800 font-semibold">{f.filename}</span>
                                <button
                                  onClick={() => onSelectJob(f.job_id)}
                                  className="text-[10px] text-indigo-600 hover:text-indigo-800 flex items-center gap-0.5 font-bold"
                                >
                                  <span>View File</span>
                                  <ExternalLink className="w-2.5 h-2.5" />
                                </button>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Primary File Jump Action */}
                  {selectedNode.type === 'file' && selectedNode.details?.job_id && (
                    <button
                      onClick={() => onSelectJob(selectedNode.details.job_id)}
                      className="w-full py-2.5 px-3 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors mt-4 shadow-sm cursor-pointer"
                    >
                      <span>Open File Analysis Tab</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  )}

                  {/* Host Log Jump Action */}
                  {selectedNode.type === 'host' && (
                    <div className="mt-4 pt-3 border-t border-slate-200">
                      <div className="flex items-center justify-between text-xs mb-3">
                        <span className="text-slate-500">Host / Machine:</span>
                        <span className="font-mono font-bold text-emerald-800">{selectedNode.details?.hostname || selectedNode.label}</span>
                      </div>
                      {selectedNode.details?.job_id && (
                        <button
                          onClick={() => onSelectJob(selectedNode.details.job_id)}
                          className="w-full py-2.5 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm cursor-pointer"
                        >
                          <Server className="w-3.5 h-3.5" />
                          <span>Open Host Event Log Tab</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW B: BINDIFF */}
      {activeSubView === 'bindiff' && (
        <BinDiffViewer bindiff={binary_diff} />
      )}

      {/* VIEW: FLEET EVTX FORENSICS */}
      {activeSubView === 'evtx_fleet' && (
        <div className="space-y-6">
          {!evtx_fleet_forensics || !evtx_fleet_forensics.available ? (
            <div className="bg-white rounded-xl border border-slate-200 p-8 text-center shadow-sm">
              <Server className="w-12 h-12 text-slate-400 mx-auto mb-3" />
              <h4 className="text-sm font-bold text-slate-800 mb-1">Fleet Telemetry Unavailable</h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                {evtx_fleet_forensics?.message ||
                  'Fleet EVTX Forensics requires two or more Windows Event Log (.evtx) files uploaded to this incident workspace.'}
              </p>
            </div>
          ) : (
            <>
              {/* Executive Fleet Security Health Banner */}
              <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shrink-0">
                      <Server className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-slate-900">
                        Fleet-Wide Windows Event Correlation & Lateral Movement Matrix
                      </h4>
                      <p className="text-xs text-slate-500">
                        Correlating telemetry across {evtx_fleet_forensics.total_hosts} hosts and{' '}
                        {evtx_fleet_forensics.total_logs} log channels.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`px-3 py-1 rounded-lg text-xs font-bold font-mono uppercase tracking-wider border ${
                        evtx_fleet_forensics.fleet_risk_level === 'CRITICAL'
                          ? 'bg-rose-50 border-rose-200 text-rose-700'
                          : evtx_fleet_forensics.fleet_risk_level === 'HIGH'
                          ? 'bg-orange-50 border-orange-200 text-orange-700'
                          : evtx_fleet_forensics.fleet_risk_level === 'MEDIUM'
                          ? 'bg-amber-50 border-amber-200 text-amber-700'
                          : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      }`}
                    >
                      Fleet Risk: {evtx_fleet_forensics.fleet_risk_level} ({evtx_fleet_forensics.fleet_risk_score}/100)
                    </span>
                  </div>
                </div>

                {/* Narrative Summary */}
                <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 leading-relaxed font-sans flex items-start gap-2.5">
                  <Layers className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                  <div>
                    <strong className="text-slate-900 font-semibold">Incident Fleet Assessment: </strong>
                    {evtx_fleet_forensics.narrative}
                  </div>
                </div>

                {/* KPI Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <div className="flex items-center justify-between text-slate-500 mb-1">
                      <span className="text-[10px] uppercase font-bold font-mono tracking-wider">Monitored Hosts</span>
                      <Server className="w-3.5 h-3.5 text-indigo-600" />
                    </div>
                    <div className="text-xl font-bold font-mono text-slate-900">{evtx_fleet_forensics.total_hosts}</div>
                    <div className="text-[10px] text-slate-500 truncate mt-0.5">
                      {evtx_fleet_forensics.hosts.map((h) => h.hostname).join(', ')}
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <div className="flex items-center justify-between text-slate-500 mb-1">
                      <span className="text-[10px] uppercase font-bold font-mono tracking-wider">Lateral Movement</span>
                      <Repeat className="w-3.5 h-3.5 text-indigo-600" />
                    </div>
                    <div className="text-xl font-bold font-mono text-slate-900">
                      {evtx_fleet_forensics.lateral_movement_chains.length}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      {evtx_fleet_forensics.lateral_movement_chains.length > 0 ? 'Active multi-hop chains' : 'No lateral hops'}
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <div className="flex items-center justify-between text-slate-500 mb-1">
                      <span className="text-[10px] uppercase font-bold font-mono tracking-wider">Sprays & Brute-Force</span>
                      <Key className="w-3.5 h-3.5 text-indigo-600" />
                    </div>
                    <div className="text-xl font-bold font-mono text-slate-900">
                      {evtx_fleet_forensics.password_spray_analysis?.total_failed_logons || 0}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      {evtx_fleet_forensics.password_spray_analysis?.campaigns?.length || 0} spray campaign(s)
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <div className="flex items-center justify-between text-slate-500 mb-1">
                      <span className="text-[10px] uppercase font-bold font-mono tracking-wider">Anti-Forensics</span>
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-600" />
                    </div>
                    <div className="text-xl font-bold font-mono text-slate-900">
                      {evtx_fleet_forensics.anti_forensics_alerts?.length || 0}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      {evtx_fleet_forensics.anti_forensics_alerts?.length > 0 ? 'Log clear detected (1102/104)' : 'Clean integrity'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Multi-EVTX View Mode Switcher: [Unified Event Log Forensics] / [Fleet Attack Graph & Analytics] */}
              <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-100 p-1.5 rounded-2xl border border-slate-200">
                <div className="flex flex-wrap items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setEvtxFleetTab('unified')}
                    className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
                      evtxFleetTab === 'unified'
                        ? 'bg-white text-indigo-700 shadow-xs font-bold ring-1 ring-slate-200/60'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Terminal className="w-4 h-4 text-indigo-600" />
                    <span>Unified Windows Event Log Forensics</span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                        evtxFleetTab === 'unified' ? 'bg-indigo-100 text-indigo-800' : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {evtx_fleet_forensics.unified_evtx_info?.total_records ?? 'All'} Events Across {evtx_fleet_forensics.total_logs} Files
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setEvtxFleetTab('analytics')}
                    className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-xl transition-all cursor-pointer ${
                      evtxFleetTab === 'analytics'
                        ? 'bg-white text-indigo-700 shadow-xs font-bold ring-1 ring-slate-200/60'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <Network className="w-4 h-4 text-indigo-600" />
                    <span>Fleet Attack Graph &amp; Lateral Movement</span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                        evtxFleetTab === 'analytics' ? 'bg-indigo-100 text-indigo-800' : 'bg-slate-200 text-slate-700'
                      }`}
                    >
                      {evtx_fleet_forensics.lateral_movement_chains.length} Chains • {evtx_fleet_forensics.total_hosts} Hosts
                    </span>
                  </button>
                </div>
                <div className="text-[11px] font-mono text-slate-500 pr-3">
                  Multi-Source Event Stream Correlation
                </div>
              </div>

              {evtxFleetTab === 'unified' ? (
                /* UNIFIED WINDOWS EVENT LOG FORENSICS TAB (IDENTICAL TO EVTX TRIAGE TAB) */
                <div className="pt-2">
                  <EvtxTriageCard
                    evtxInfo={evtx_fleet_forensics.unified_evtx_info || undefined}
                    filename={`Fleet Unified (${evtx_fleet_forensics.total_logs} .evtx files)`}
                    antiAnalysis={evtx_fleet_forensics.combined_anti_analysis}
                  />
                </div>
              ) : (
                <div className="space-y-6">
                  {/* 1. Cross-Host Lateral Movement Chains */}
                  <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                      <div>
                        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                          <Repeat className="w-4 h-4 text-indigo-600" />
                          Cross-Host Lateral Movement Chains
                        </h4>
                        <p className="text-xs text-slate-500">
                          Chronological progression of attacker traversal across networked endpoints.
                        </p>
                      </div>
                      <span className="text-xs font-mono font-bold text-indigo-600">
                        {evtx_fleet_forensics.lateral_movement_chains.length} Chains Detected
                      </span>
                    </div>

                {evtx_fleet_forensics.lateral_movement_chains.length === 0 ? (
                  <div className="text-center py-6 text-slate-500 text-xs">
                    No cross-host lateral movement chains identified in parsed event logs.
                  </div>
                ) : (
                  <div className="space-y-4">
                    {evtx_fleet_forensics.lateral_movement_chains.map((chain) => (
                      <div
                        key={chain.chain_id}
                        className="bg-slate-50/50 rounded-xl border border-slate-200 p-4 space-y-3"
                      >
                        {/* Chain Header */}
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-indigo-100 text-indigo-800">
                              {chain.mitre_id}
                            </span>
                            <span className="text-xs font-bold text-slate-800">{chain.technique}</span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                chain.confidence === 'HIGH'
                                  ? 'bg-rose-100 text-rose-800'
                                  : 'bg-amber-100 text-amber-800'
                              }`}
                            >
                              {chain.confidence} CONFIDENCE
                            </span>
                          </div>
                          <div className="text-[10px] font-mono text-slate-500">
                            {chain.timestamp ? new Date(chain.timestamp).toLocaleString() : ''}
                          </div>
                        </div>

                        {/* Visual Host Traversal Node Hop */}
                        <div className="flex items-center gap-3 bg-white p-3 rounded-lg border border-slate-200 flex-wrap">
                          <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-slate-800">
                            <Server className="w-4 h-4 text-indigo-600" />
                            <span>{chain.source_host}</span>
                          </div>
                          <div className="flex items-center gap-1 text-slate-400">
                            <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                              {chain.protocol}
                            </span>
                            <ArrowRight className="w-4 h-4 text-indigo-600" />
                          </div>
                          <div className="flex items-center gap-1.5 font-mono text-xs font-bold text-slate-800">
                            <Server className="w-4 h-4 text-rose-600" />
                            <span>{chain.target_host}</span>
                          </div>
                          <div className="ml-auto flex items-center gap-3">
                            <div className="text-xs font-mono text-slate-600">
                              Compromised Account: <strong className="text-slate-900">{chain.user_account}</strong>
                            </div>
                          </div>
                        </div>

                        {/* Chronological Stages */}
                        {chain.stages && chain.stages.length > 0 && (
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                            {chain.stages.map((stage) => (
                              <div
                                key={stage.step}
                                className="bg-white p-2.5 rounded-lg border border-slate-200 text-xs space-y-1"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="text-[10px] font-mono font-bold text-indigo-600">
                                    Stage {stage.step}
                                  </span>
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono bg-slate-100 text-slate-600">
                                    Event {stage.event_id}
                                  </span>
                                </div>
                                <div className="font-semibold text-slate-800">{stage.title}</div>
                                <div className="text-[11px] text-slate-500 font-mono">{stage.description}</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 2. Multi-Host Telemetry Comparison Matrix */}
              <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                      <Server className="w-4 h-4 text-indigo-600" />
                      Multi-Host Telemetry Comparison Matrix
                    </h4>
                    <p className="text-xs text-slate-500">
                      Cross-endpoint telemetry, threat volumes, and active accounts per host artifact.
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                        <th className="p-3 font-semibold">Endpoint / Hostname</th>
                        <th className="p-3 font-semibold">Log File / Channel</th>
                        <th className="p-3 font-semibold text-right">Total Events</th>
                        <th className="p-3 font-semibold text-right">Threat Events</th>
                        <th className="p-3 font-semibold">Observed Users</th>
                        <th className="p-3 font-semibold">Source IPs</th>
                        <th className="p-3 font-semibold text-center">Anti-Forensics</th>
                        <th className="p-3 font-semibold text-center">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-sans">
                      {evtx_fleet_forensics.hosts.map((host) => (
                        <tr key={host.job_id} className="hover:bg-slate-50/80 transition-colors">
                          <td className="p-3">
                            <div className="font-mono font-bold text-slate-900 flex items-center gap-1.5">
                              <Server className="w-3.5 h-3.5 text-indigo-600" />
                              <span>{host.hostname}</span>
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="text-slate-800 font-semibold">{host.filename}</div>
                            <div className="text-[10px] text-slate-400 font-mono">{host.channel || 'Security'}</div>
                          </td>
                          <td className="p-3 text-right font-mono text-slate-700">
                            {host.total_events.toLocaleString()}
                          </td>
                          <td className="p-3 text-right font-mono">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[11px] font-bold ${
                                host.threat_events_count > 0
                                  ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                  : 'bg-slate-100 text-slate-600'
                              }`}
                            >
                              {host.threat_events_count}
                            </span>
                          </td>
                          <td className="p-3">
                            <div className="flex flex-wrap gap-1 max-w-xs">
                              {host.unique_users.slice(0, 3).map((u, uIdx) => (
                                <span
                                  key={uIdx}
                                  className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-100 text-slate-700"
                                >
                                  {u}
                                </span>
                              ))}
                              {host.unique_users.length > 3 && (
                                <span className="text-[10px] font-mono text-slate-400">
                                  +{host.unique_users.length - 3} more
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="p-3">
                            <div className="flex flex-wrap gap-1 max-w-xs">
                              {host.unique_ips.length > 0 ? (
                                host.unique_ips.slice(0, 2).map((ip, ipIdx) => (
                                  <span
                                    key={ipIdx}
                                    className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700"
                                  >
                                    {ip}
                                  </span>
                                ))
                              ) : (
                                <span className="text-[10px] text-slate-400 italic">None logged</span>
                              )}
                            </div>
                          </td>
                          <td className="p-3 text-center">
                            {host.has_log_cleared ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800">
                                CLEARED (1102)
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-50 text-emerald-700">
                                Normal
                              </span>
                            )}
                          </td>
                          <td className="p-3 text-center">
                            <button
                              onClick={() => onSelectJob(host.job_id)}
                              className="px-2.5 py-1 rounded text-xs font-semibold bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 transition-colors inline-flex items-center gap-1"
                            >
                              <span>Inspect Tab</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 3. Fleet Password Spray & Distributed Brute-Force Matrix */}
              {evtx_fleet_forensics.password_spray_analysis && (
                <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                        <Key className="w-4 h-4 text-indigo-600" />
                        Fleet Password Spray & Distributed Brute-Force Matrix
                      </h4>
                      <p className="text-xs text-slate-500">
                        Horizontal authentication failure tracking across multiple endpoints and accounts (Event 4625).
                      </p>
                    </div>
                    <span className="text-xs font-mono font-bold text-rose-600">
                      {evtx_fleet_forensics.password_spray_analysis.total_failed_logons} Total Failures
                    </span>
                  </div>

                  {/* Campaigns summary */}
                  {evtx_fleet_forensics.password_spray_analysis.campaigns.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {evtx_fleet_forensics.password_spray_analysis.campaigns.map((camp, cIdx) => (
                        <div
                          key={cIdx}
                          className="bg-rose-50/50 border border-rose-200 rounded-lg p-3 flex items-start gap-2.5"
                        >
                          <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-bold text-rose-900">{camp.pattern}</span>
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-rose-200 text-rose-900 uppercase">
                                {camp.threat_level}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-600">{camp.type}</p>
                            <div className="text-[10px] font-mono text-rose-800 font-semibold">
                              Failures Recorded: {camp.failures}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Users Matrix Table */}
                  {evtx_fleet_forensics.password_spray_analysis.user_matrix.length > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                            <th className="p-3 font-semibold">Target Account</th>
                            <th className="p-3 font-semibold text-right">Failure Count</th>
                            <th className="p-3 font-semibold">Targeted Hosts</th>
                            <th className="p-3 font-semibold">Source IPs</th>
                            <th className="p-3 font-semibold text-center">Threat Classification</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 font-sans">
                          {evtx_fleet_forensics.password_spray_analysis.user_matrix.map((userEntry, uIdx) => (
                            <tr key={uIdx} className="hover:bg-slate-50/80 transition-colors">
                              <td className="p-3 font-mono font-bold text-slate-900 flex items-center gap-1.5">
                                <User className="w-3.5 h-3.5 text-slate-500" />
                                <span>{userEntry.username}</span>
                              </td>
                              <td className="p-3 text-right font-mono font-bold text-rose-600">
                                {userEntry.total_failures}
                              </td>
                              <td className="p-3">
                                <div className="flex flex-wrap gap-1">
                                  {userEntry.hosts_targeted.map((h, hIdx) => (
                                    <span
                                      key={hIdx}
                                      className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-100 text-slate-700"
                                    >
                                      {h}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="p-3">
                                <div className="flex flex-wrap gap-1">
                                  {userEntry.source_ips.map((ip, ipIdx) => (
                                    <span
                                      key={ipIdx}
                                      className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700"
                                    >
                                      {ip}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="p-3 text-center">
                                {userEntry.is_spray_target ? (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800">
                                    SPRAY TARGET
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-100 text-slate-600">
                                    Isolated Failure
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="text-center py-4 text-xs text-slate-500">
                      No failed logon events (Event 4625) recorded across fleet logs.
                    </div>
                  )}
                </div>
              )}

              {/* 4. Cross-Host Process & LOLBin Divergence */}
              {evtx_fleet_forensics.lolbin_divergence && evtx_fleet_forensics.lolbin_divergence.length > 0 && (
                <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                        <Terminal className="w-4 h-4 text-indigo-600" />
                        Cross-Host Process & LOLBin Divergence
                      </h4>
                      <p className="text-xs text-slate-500">
                        Dual-use execution binaries and anomalous commands launched across endpoints.
                      </p>
                    </div>
                    <span className="text-xs font-mono font-bold text-indigo-600">
                      {evtx_fleet_forensics.lolbin_divergence.length} Suspicious Executions
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                          <th className="p-3 font-semibold">Host</th>
                          <th className="p-3 font-semibold">Binary</th>
                          <th className="p-3 font-semibold">Command Line</th>
                          <th className="p-3 font-semibold">Parent Process</th>
                          <th className="p-3 font-semibold">User</th>
                          <th className="p-3 font-semibold">Technique</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-sans">
                        {evtx_fleet_forensics.lolbin_divergence.map((proc, pIdx) => (
                          <tr key={pIdx} className="hover:bg-slate-50/80 transition-colors">
                            <td className="p-3 font-mono font-bold text-slate-800">{proc.host}</td>
                            <td className="p-3">
                              <span className="px-1.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
                                {proc.process_name}
                              </span>
                            </td>
                            <td className="p-3 max-w-md">
                              <div className="flex items-center gap-1.5">
                                <span className="font-mono text-[11px] text-slate-700 truncate block">
                                  {proc.command_line}
                                </span>
                                <button
                                  onClick={() => handleCopy(proc.command_line, `proc-${pIdx}`)}
                                  className="text-slate-400 hover:text-slate-700 p-1 shrink-0"
                                  title="Copy Command Line"
                                >
                                  {copiedKey === `proc-${pIdx}` ? (
                                    <Check className="w-3 h-3 text-emerald-600" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                </button>
                              </div>
                            </td>
                            <td className="p-3 font-mono text-slate-500 text-[11px]">{proc.parent_process}</td>
                            <td className="p-3 font-mono text-slate-700 text-[11px]">{proc.user}</td>
                            <td className="p-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                                {proc.mitre_id}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* 5. Anti-Forensics & Privilege Escalation Alerts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Left: Anti-Forensics (Log Clear Events) */}
                <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-rose-700 flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4 text-rose-600" />
                      Anti-Forensics & Log Tampering Alerts
                    </h4>
                    <span className="text-xs font-mono font-bold text-rose-600">
                      {evtx_fleet_forensics.anti_forensics_alerts?.length || 0} Alert(s)
                    </span>
                  </div>

                  {evtx_fleet_forensics.anti_forensics_alerts &&
                  evtx_fleet_forensics.anti_forensics_alerts.length > 0 ? (
                    <div className="space-y-2">
                      {evtx_fleet_forensics.anti_forensics_alerts.map((alert, aIdx) => (
                        <div
                          key={aIdx}
                          className="bg-rose-50 border border-rose-200 rounded-lg p-3 space-y-1 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-rose-900 font-mono">
                              Event {alert.event_id} ({alert.host})
                            </span>
                            <span className="text-[10px] font-mono text-rose-700">
                              {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : ''}
                            </span>
                          </div>
                          <div className="text-slate-800 font-semibold">{alert.title}</div>
                          <div className="text-[11px] text-slate-600 font-mono">
                            Cleared by: <strong>{alert.user}</strong> on channel <em>{alert.channel}</em>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-6 text-xs text-slate-500">
                      No event log tampering or clearing events (1102/104) detected across endpoints.
                    </div>
                  )}
                </div>

                {/* Right: Privilege Escalation & Admin Role Changes */}
                <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-amber-800 flex items-center gap-1.5">
                      <Key className="w-4 h-4 text-amber-600" />
                      Fleet Privilege Escalation Events
                    </h4>
                    <span className="text-xs font-mono font-bold text-amber-700">
                      {evtx_fleet_forensics.privilege_escalation_events?.length || 0} Event(s)
                    </span>
                  </div>

                  {evtx_fleet_forensics.privilege_escalation_events &&
                  evtx_fleet_forensics.privilege_escalation_events.length > 0 ? (
                    <div className="space-y-2">
                      {evtx_fleet_forensics.privilege_escalation_events.map((priv, pIdx) => (
                        <div
                          key={pIdx}
                          className="bg-amber-50 border border-amber-200 rounded-lg p-3 space-y-1 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-amber-900 font-mono">
                              Event {priv.event_id} ({priv.host})
                            </span>
                            <span className="text-[10px] font-mono text-amber-700">
                              {priv.timestamp ? new Date(priv.timestamp).toLocaleString() : ''}
                            </span>
                          </div>
                          <div className="text-slate-800 font-semibold">
                            User: <strong className="font-mono">{priv.user}</strong>
                          </div>
                          <div className="text-[11px] text-slate-600 font-mono truncate">
                            Privileges: {priv.privileges}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-6 text-xs text-slate-500">
                      No special privilege assignment (Event 4672) or group manipulation detected.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )}

      {/* VIEW: PCAP FLEET NETWORK INTELLIGENCE */}
      {activeSubView === 'pcap_fleet' && data.pcap_fleet_intelligence && (
        <div className="space-y-6">
          {/* Header Banner */}
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-5">
              <div className="space-y-1">
                <div className="flex items-center gap-2.5">
                  <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                    <Radio className="w-5 h-5 text-indigo-600" />
                    Fleet PCAP Network Intelligence
                  </h3>
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                    data.pcap_fleet_intelligence.fleet_risk_level === 'CRITICAL'
                      ? 'bg-rose-100 text-rose-800 border border-rose-200'
                      : data.pcap_fleet_intelligence.fleet_risk_level === 'HIGH'
                      ? 'bg-amber-100 text-amber-800 border border-amber-200'
                      : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                  }`}>
                    {data.pcap_fleet_intelligence.fleet_risk_level} (Score {data.pcap_fleet_intelligence.fleet_risk_score}/100)
                  </span>
                </div>
                <p className="text-xs text-slate-500">
                  Cross-sensor packet correlation across {data.pcap_fleet_intelligence.total_captures} capture file(s) and {data.pcap_fleet_intelligence.total_fleet_packets?.toLocaleString() || 0} total packets.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <div className="text-xs text-slate-400 font-mono">Total Transferred</div>
                  <div className="text-sm font-bold font-mono text-slate-800">
                    {((data.pcap_fleet_intelligence.total_fleet_bytes || 0) / 1024).toFixed(1)} KB
                  </div>
                </div>
              </div>
            </div>

            {data.pcap_fleet_intelligence.narrative && (
              <p className="text-xs text-slate-700 leading-relaxed mt-4 bg-slate-50 p-3 rounded-xl border border-slate-200/80 font-mono">
                {data.pcap_fleet_intelligence.narrative}
              </p>
            )}
          </div>

          {/* Sensor Captures Matrix */}
          {data.pcap_fleet_intelligence.captures_summary && data.pcap_fleet_intelligence.captures_summary.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                <Server className="w-4 h-4 text-indigo-600" />
                Network Capture Sensor Matrix
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                      <th className="p-3 font-semibold">Sensor / File</th>
                      <th className="p-3 font-semibold text-right">Packets</th>
                      <th className="p-3 font-semibold text-right">Duration</th>
                      <th className="p-3 font-semibold">Protocols</th>
                      <th className="p-3 font-semibold text-right">Conversations</th>
                      <th className="p-3 font-semibold text-right">IPs / Domains</th>
                      <th className="p-3 font-semibold text-right">Credentials</th>
                      <th className="p-3 font-semibold text-right">Beaconing</th>
                      <th className="p-3 font-semibold text-center">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-sans">
                    {data.pcap_fleet_intelligence.captures_summary.map((cap) => (
                      <tr key={cap.job_id} className="hover:bg-slate-50/80 transition-colors">
                        <td className="p-3 font-mono font-bold text-slate-900">
                          {cap.filename}
                        </td>
                        <td className="p-3 text-right font-mono text-slate-700">
                          {cap.packet_count?.toLocaleString()}
                        </td>
                        <td className="p-3 text-right font-mono text-slate-600">
                          {cap.duration_seconds}s
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {cap.protocols?.slice(0, 4).map((p, pIdx) => (
                              <span key={pIdx} className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 border border-indigo-200">
                                {p}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="p-3 text-right font-mono text-slate-700">
                          {cap.conversations_count}
                        </td>
                        <td className="p-3 text-right font-mono text-slate-700">
                          {cap.unique_ips_count} / {cap.unique_domains_count}
                        </td>
                        <td className="p-3 text-right font-mono">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            cap.credentials_count > 0 ? 'bg-amber-100 text-amber-800' : 'text-slate-400'
                          }`}>
                            {cap.credentials_count}
                          </span>
                        </td>
                        <td className="p-3 text-right font-mono">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            cap.beaconing_count > 0 ? 'bg-rose-100 text-rose-800' : 'text-slate-400'
                          }`}>
                            {cap.beaconing_count}
                          </span>
                        </td>
                        <td className="p-3 text-center">
                          <button
                            onClick={() => onSelectJob(cap.job_id)}
                            className="px-2.5 py-1 rounded text-xs font-semibold bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 transition-colors inline-flex items-center gap-1 cursor-pointer"
                          >
                            <span>Inspect</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Cross-Capture IP Bridge & Overlap */}
          {data.pcap_fleet_intelligence.cross_capture_ips && data.pcap_fleet_intelligence.cross_capture_ips.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                  <Globe className="w-4 h-4 text-indigo-600" />
                  Cross-Capture Endpoint Bridges ({data.pcap_fleet_intelligence.cross_capture_ips.length})
                </h4>
                <span className="text-xs font-mono text-indigo-600">IPs appearing across &gt;1 sensor capture</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                      <th className="p-3 font-semibold">IP Address</th>
                      <th className="p-3 font-semibold">Classification</th>
                      <th className="p-3 font-semibold">Country / ASN</th>
                      <th className="p-3 font-semibold">Seen In Captures</th>
                      <th className="p-3 font-semibold">Observed Roles</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-sans">
                    {data.pcap_fleet_intelligence.cross_capture_ips.map((ipObj, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="p-3 font-mono font-bold text-slate-900">
                          {ipObj.ip}
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            ipObj.is_private ? 'bg-slate-100 text-slate-700' : 'bg-rose-50 text-rose-700 border border-rose-200'
                          }`}>
                            {ipObj.is_private ? 'INTERNAL RFC1918' : 'EXTERNAL / C2'}
                          </span>
                        </td>
                        <td className="p-3 text-slate-700 font-mono text-[11px]">
                          {ipObj.country} {ipObj.city && ipObj.city !== '-' ? `• ${ipObj.city}` : ''} {ipObj.asn && ipObj.asn !== '-' ? `(${ipObj.asn})` : ''}
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {ipObj.seen_in_captures.map((fname, fIdx) => (
                              <span key={fIdx} className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 border border-indigo-200">
                                {fname}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="p-3 text-[11px] font-mono text-slate-600">
                          {ipObj.roles?.join(', ') || 'traffic'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Cross-Capture Lateral Movement Network Traffic */}
          {data.pcap_fleet_intelligence.lateral_network_flows && data.pcap_fleet_intelligence.lateral_network_flows.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                  <Repeat className="w-4 h-4 text-indigo-600" />
                  Internal Lateral Network Connections ({data.pcap_fleet_intelligence.lateral_network_flows.length})
                </h4>
                <span className="text-xs font-mono text-rose-600 font-bold">SMB, RPC, RDP, SSH, WinRM internal flows</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                      <th className="p-3 font-semibold">Source Host</th>
                      <th className="p-3 font-semibold"></th>
                      <th className="p-3 font-semibold">Target Host</th>
                      <th className="p-3 font-semibold">Service / Port</th>
                      <th className="p-3 font-semibold text-right">Bytes</th>
                      <th className="p-3 font-semibold">Sensor Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-sans">
                    {data.pcap_fleet_intelligence.lateral_network_flows.map((lat, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="p-3 font-mono font-bold text-slate-800">
                          {lat.src_ip}
                        </td>
                        <td className="p-3 text-slate-400">
                          <ArrowRight className="w-3.5 h-3.5 text-indigo-600" />
                        </td>
                        <td className="p-3 font-mono font-bold text-slate-800">
                          {lat.dst_ip}
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
                            {lat.service} (Port {lat.port})
                          </span>
                        </td>
                        <td className="p-3 text-right font-mono text-slate-600">
                          {lat.bytes?.toLocaleString()} B
                        </td>
                        <td className="p-3 font-mono text-[11px] text-slate-500">
                          {lat.filename}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Shared Overheard Credentials */}
          {data.pcap_fleet_intelligence.shared_credentials && data.pcap_fleet_intelligence.shared_credentials.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                  <Key className="w-4 h-4 text-amber-600" />
                  Fleet Overheard Credentials ({data.pcap_fleet_intelligence.shared_credentials.length})
                </h4>
                <span className="text-xs font-mono text-amber-600">Plaintext auth, Kerberos, and NTLM hashes</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                      <th className="p-3 font-semibold">User Account</th>
                      <th className="p-3 font-semibold">Protocols</th>
                      <th className="p-3 font-semibold">Seen In Captures</th>
                      <th className="p-3 font-semibold">Target Server(s)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-sans">
                    {data.pcap_fleet_intelligence.shared_credentials.map((cred, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="p-3 font-mono font-bold text-slate-900 flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-slate-400" />
                          <span>{cred.username}</span>
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {cred.protocols.map((p, pIdx) => (
                              <span key={pIdx} className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-amber-50 text-amber-800 border border-amber-200">
                                {p}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {cred.seen_in_captures.map((fname, fIdx) => (
                              <span key={fIdx} className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 border border-indigo-200">
                                {fname}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-slate-600">
                          {cred.targets?.join(', ') || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Active Beaconing Flows */}
          {data.pcap_fleet_intelligence.all_beaconing && data.pcap_fleet_intelligence.all_beaconing.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-rose-600" />
                  Active C2 Beaconing Channels ({data.pcap_fleet_intelligence.all_beaconing.length})
                </h4>
                <span className="text-xs font-mono text-rose-600">Regular interval beaconing indicators</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-[10px] font-mono uppercase text-slate-500">
                      <th className="p-3 font-semibold">C2 Endpoint</th>
                      <th className="p-3 font-semibold">Port</th>
                      <th className="p-3 font-semibold text-right">Interval</th>
                      <th className="p-3 font-semibold text-right">Jitter</th>
                      <th className="p-3 font-semibold">Sensor Capture</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-sans">
                    {data.pcap_fleet_intelligence.all_beaconing.map((b, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="p-3 font-mono font-bold text-rose-700">
                          {b.dst_ip}
                        </td>
                        <td className="p-3 font-mono text-slate-700">
                          {b.dst_port}
                        </td>
                        <td className="p-3 text-right font-mono font-bold text-slate-800">
                          {b.interval_seconds}s
                        </td>
                        <td className="p-3 text-right font-mono text-slate-600">
                          {b.jitter_percent}%
                        </td>
                        <td className="p-3 font-mono text-[11px] text-slate-600">
                          {b.capture_file}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* VIEW C: UNIFIED TIMELINE */}
      {activeSubView === 'timeline' && (
        <div className="space-y-6">
          {/* Staging Progression Cards */}
          {timeline_comparison.staging_sequence && timeline_comparison.staging_sequence.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
              <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-700 mb-3 flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-indigo-600" />
                Detected Multi-Stage Attack Progression
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {timeline_comparison.staging_sequence.map((seq, idx) => (
                  <div key={idx} className="bg-slate-50 border border-slate-200 rounded-lg p-3 relative overflow-hidden">
                    <span className="text-[10px] font-mono text-indigo-600 font-bold block mb-1">
                      Step {idx + 1}
                    </span>
                    <div className="text-xs font-bold text-slate-800">{seq.phase}</div>
                    <div className="text-[11px] text-slate-500 font-mono truncate mt-0.5">{seq.filename}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Timeline Table or Multi-Host Swimlane View */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50 flex-wrap gap-3">
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Chronological Multi-File Forensic Event Timeline
                </h4>
                <p className="text-xs text-slate-500">
                  Total Events: {timeline_comparison.total_events} • Anomalies: {timeline_comparison.anomalies_count}
                </p>
              </div>

              <div className="flex items-center gap-2">
                {evtxJobs.length >= 2 && (
                  <div className="flex items-center bg-slate-200/80 rounded-lg p-0.5 border border-slate-300 text-xs">
                    <button
                      onClick={() => setTimelineViewMode('table')}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all font-semibold cursor-pointer ${
                        timelineViewMode === 'table'
                          ? 'bg-white text-slate-900 shadow-sm'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      <SlidersHorizontal className="w-3.5 h-3.5" />
                      <span>Unified Table</span>
                    </button>
                    <button
                      onClick={() => setTimelineViewMode('swimlanes')}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all font-semibold cursor-pointer ${
                        timelineViewMode === 'swimlanes'
                          ? 'bg-indigo-600 text-white shadow-sm'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      <Layers className="w-3.5 h-3.5" />
                      <span>Multi-Host Swimlanes</span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                          timelineViewMode === 'swimlanes'
                            ? 'bg-white/20 text-white'
                            : 'bg-indigo-100 text-indigo-700'
                        }`}
                      >
                        {evtxJobs.length} Logs
                      </span>
                    </button>
                  </div>
                )}

                {timelineViewMode === 'table' && (
                  <button
                    onClick={handleExportTimeline}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 hover:text-slate-900 shadow-sm transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-slate-500" />
                    <span>Export CSV</span>
                  </button>
                )}
              </div>
            </div>

            {timelineViewMode === 'swimlanes' && evtxJobs.length >= 2 ? (
              <div className="p-5 bg-slate-50/50 border-t border-slate-200">
                <MultiEvtxSwimlaneView
                  jobs={jobs}
                  correlationEvents={timeline_comparison.events}
                  lateralChains={evtx_fleet_forensics?.lateral_movement_chains}
                  onSelectJob={onSelectJob}
                  onSwitchToTable={() => setTimelineViewMode('table')}
                />
              </div>
            ) : (
              <>
                {/* Timeline Filter Controls */}
                <div className="p-3.5 border-b border-slate-100 bg-white flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[280px]">
                {/* Search Input */}
                <div className="relative flex-1 min-w-[200px] max-w-md">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={timelineSearch}
                    onChange={(e) => setTimelineSearch(e.target.value)}
                    placeholder="Search events, descriptions, computers, users..."
                    className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                  />
                  {timelineSearch && (
                    <button
                      onClick={() => setTimelineSearch('')}
                      className="text-[10px] text-slate-400 hover:text-slate-600 absolute right-2.5 top-1/2 -translate-y-1/2 font-mono cursor-pointer"
                    >
                      clear
                    </button>
                  )}
                </div>

                {/* File Dropdown Filter */}
                {uniqueTimelineFiles.length > 1 && (
                  <select
                    value={selectedTimelineFile}
                    onChange={(e) => setSelectedTimelineFile(e.target.value)}
                    className="text-xs bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-700 font-mono focus:outline-none cursor-pointer"
                  >
                    <option value="all">All Files ({uniqueTimelineFiles.length})</option>
                    {uniqueTimelineFiles.map((fn, idx) => (
                      <option key={idx} value={fn}>{fn}</option>
                    ))}
                  </select>
                )}

                {/* Host Dropdown Filter */}
                {uniqueTimelineHosts.length > 1 && (
                  <select
                    value={selectedTimelineHost}
                    onChange={(e) => setSelectedTimelineHost(e.target.value)}
                    className="text-xs bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-700 font-mono focus:outline-none cursor-pointer"
                  >
                    <option value="all">All Hosts ({uniqueTimelineHosts.length})</option>
                    {uniqueTimelineHosts.map((h, idx) => (
                      <option key={idx} value={h}>{h}</option>
                    ))}
                  </select>
                )}

                {/* Anomalies Only Toggle */}
                <label className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={anomaliesOnly}
                    onChange={(e) => setAnomaliesOnly(e.target.checked)}
                    className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                  />
                  <span>Anomalies Only</span>
                  {timeline_comparison.anomalies_count > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rose-100 text-rose-800 font-bold">
                      {timeline_comparison.anomalies_count}
                    </span>
                  )}
                </label>
              </div>

              <div className="text-xs font-mono text-slate-500">
                Showing {filteredTimelineEvents.length} of {timeline_comparison.total_events} events
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-slate-600 font-mono text-[11px] border-b border-slate-200">
                    <th className="py-2.5 px-3">Timestamp (UTC)</th>
                    <th className="py-2.5 px-3">File Source</th>
                    <th className="py-2.5 px-3">Host / Asset</th>
                    <th className="py-2.5 px-3">Staging Phase</th>
                    <th className="py-2.5 px-3">Event / Action</th>
                    <th className="py-2.5 px-3">User</th>
                    <th className="py-2.5 px-3">Description</th>
                    <th className="py-2.5 px-3">Flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {filteredTimelineEvents.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-slate-400 text-xs font-mono">
                        No events match current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredTimelineEvents.map((ev, idx) => (
                      <tr key={idx} className={`hover:bg-slate-50 ${ev.is_anomaly ? 'bg-rose-50/40' : ''}`}>
                        <td className="py-2.5 px-3 text-slate-800 whitespace-nowrap">{ev.timestamp || '-'}</td>
                        <td className="py-2.5 px-3 font-semibold text-slate-900 whitespace-nowrap">
                          <button
                            onClick={() => onSelectJob(ev.job_id)}
                            className="hover:text-indigo-600 hover:underline flex items-center gap-1 cursor-pointer"
                          >
                            <span className="truncate max-w-[130px]">{ev.filename}</span>
                            <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                          </button>
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-700">
                            <Server className="w-2.5 h-2.5 text-slate-500" />
                            <span className="truncate max-w-[110px]">{ev.computer || '-'}</span>
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-600 whitespace-nowrap">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-50 text-indigo-800 border border-indigo-200">
                            {ev.staging_phase}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-bold text-slate-800">{ev.event}</td>
                        <td className="py-2.5 px-3 text-slate-700 whitespace-nowrap">
                          {ev.user && ev.user !== '-' ? (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-50 text-amber-800">
                              <User className="w-2.5 h-2.5" />
                              <span>{ev.user}</span>
                            </span>
                          ) : (
                            <span className="text-slate-400 text-[10px] font-mono">-</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-600 max-w-sm">
                          <ReferencedText
                            text={ev.description}
                            workspaceJobs={jobs}
                            onSelectJob={onSelectJob}
                          />
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1">
                            {ev.is_anomaly && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                                ANOMALY
                              </span>
                            )}
                            {ev.is_timestomp && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200">
                                TIMESTOMP
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  )}

      {/* VIEW D: HASHES & SIMILARITY */}
      {activeSubView === 'hashes' && (
        <div className="space-y-6">
          {/* Cryptographic Hash Comparison Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 bg-slate-50">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Multi-Sample Cryptographic Hash Matrix
              </h4>
              <p className="text-xs text-slate-500">
                Side-by-side verification of MD5, SHA1, SHA256, Imphash, and Rich Header hashes.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-slate-600 font-mono text-[11px] border-b border-slate-200">
                    <th className="py-2.5 px-3">File</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">SHA256</th>
                    <th className="py-2.5 px-3">MD5</th>
                    <th className="py-2.5 px-3">Imphash</th>
                    <th className="py-2.5 px-3">Rich Header MD5</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {hash_comparison.files.map((f, idx) => (
                    <tr key={idx} className="hover:bg-slate-50">
                      <td className="py-2.5 px-3 font-bold text-slate-900">
                        <button
                          onClick={() => onSelectJob(f.job_id)}
                          className="hover:text-indigo-600 hover:underline flex items-center gap-1"
                        >
                          <span className="truncate max-w-[150px]">{f.filename}</span>
                          <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                        </button>
                      </td>
                      <td className="py-2.5 px-3 uppercase text-[10px] text-slate-500">{f.category}</td>
                      <td className="py-2.5 px-3 text-slate-700">
                        <div className="flex items-center gap-1">
                          <span>{f.sha256 ? `${f.sha256.slice(0, 16)}...` : '-'}</span>
                          {f.sha256 && (
                            <button
                              onClick={() => handleCopy(f.sha256, `sha_${f.job_id}`)}
                              className="text-slate-400 hover:text-slate-700 p-0.5"
                            >
                              {copiedKey === `sha_${f.job_id}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-700">
                        <div className="flex items-center gap-1">
                          <span>{f.md5 ? `${f.md5.slice(0, 12)}...` : '-'}</span>
                          {f.md5 && (
                            <button
                              onClick={() => handleCopy(f.md5, `md5_${f.job_id}`)}
                              className="text-slate-400 hover:text-slate-700 p-0.5"
                            >
                              {copiedKey === `md5_${f.job_id}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-700">{f.imphash || '-'}</td>
                      <td className="py-2.5 px-3 text-slate-700">{f.rich_header_hash || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pairwise Hash Similarity Matrix */}
          {hash_comparison.pairwise_matrix && hash_comparison.pairwise_matrix.length > 0 && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 mb-3">
                Pairwise Structural & Hash Similarity Matrix
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {hash_comparison.pairwise_matrix.map((p, idx) => (
                  <div key={idx} className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold text-slate-800">
                      {(() => {
                        const jobA = jobs.find(j => (p as any).job_id_a ? (j.jobId === (p as any).job_id_a) : j.filename.toLowerCase() === p.file_a.toLowerCase());
                        const jobB = jobs.find(j => (p as any).job_id_b ? (j.jobId === (p as any).job_id_b) : j.filename.toLowerCase() === p.file_b.toLowerCase());
                        return (
                          <>
                            {jobA ? (
                              <button
                                onClick={() => onSelectJob(jobA.jobId)}
                                className="truncate max-w-[160px] text-left font-bold text-indigo-700 hover:text-indigo-900 hover:underline flex items-center gap-1 cursor-pointer"
                                title={`Open analysis for ${p.file_a}`}
                              >
                                <span className="truncate">{p.file_a}</span>
                                <ExternalLink className="w-3 h-3 text-indigo-500 shrink-0" />
                              </button>
                            ) : (
                              <span className="truncate max-w-[160px]">{p.file_a}</span>
                            )}
                            <GitCompare className="w-3.5 h-3.5 text-slate-400 shrink-0 mx-2" />
                            {jobB ? (
                              <button
                                onClick={() => onSelectJob(jobB.jobId)}
                                className="truncate max-w-[160px] text-right font-bold text-indigo-700 hover:text-indigo-900 hover:underline flex items-center justify-end gap-1 cursor-pointer"
                                title={`Open analysis for ${p.file_b}`}
                              >
                                <span className="truncate">{p.file_b}</span>
                                <ExternalLink className="w-3 h-3 text-indigo-500 shrink-0" />
                              </button>
                            ) : (
                              <span className="truncate max-w-[160px]">{p.file_b}</span>
                            )}
                          </>
                        );
                      })()}
                    </div>

                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[11px] font-mono text-slate-500">Overall Match:</span>
                      <span className="text-xs font-mono font-bold text-indigo-600">
                        {p.overall_similarity_pct}%
                      </span>
                    </div>

                    <div className="flex items-center gap-2 pt-1 text-[10px] font-mono text-slate-600">
                      <span className={`px-1.5 py-0.2 rounded border ${p.imphash_match ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-400 border-slate-200'}`}>
                        Imphash: {p.imphash_match ? 'MATCH' : 'DIFF'}
                      </span>
                      <span className={`px-1.5 py-0.2 rounded border ${p.rich_header_match ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-100 text-slate-400 border-slate-200'}`}>
                        Rich Header: {p.rich_header_match ? 'MATCH' : 'DIFF'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Shared Components / Payloads */}
          {hash_comparison.shared_components && hash_comparison.shared_components.length > 0 && (
            <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-4">
              <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-amber-900 mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                Shared Dropped / Embedded Payload Matches Across Samples
              </h4>
              <div className="space-y-2">
                {hash_comparison.shared_components.map((comp, idx) => (
                  <div key={idx} className="bg-white p-3 rounded-lg border border-amber-200 text-xs font-mono">
                    <div className="font-bold text-slate-800 mb-1">Hash: {comp.hash}</div>
                    <div className="text-[11px] text-slate-600">Found inside:</div>
                    <ul className="list-disc list-inside mt-1 space-y-0.5 text-slate-700">
                      {comp.sightings.map((s, sIdx) => {
                        const sJob = jobs.find(j => (s as any).job_id ? (j.jobId === (s as any).job_id) : j.filename.toLowerCase() === s.filename.toLowerCase());
                        return (
                          <li key={sIdx}>
                            {sJob ? (
                              <button
                                onClick={() => onSelectJob(sJob.jobId)}
                                className="font-bold text-indigo-700 hover:text-indigo-900 hover:underline cursor-pointer inline-flex items-center gap-1"
                                title={`Open analysis for ${s.filename}`}
                              >
                                <span>{s.filename}</span>
                                <ExternalLink className="w-3 h-3 text-indigo-500 inline" />
                              </button>
                            ) : (
                              <strong>{s.filename}</strong>
                            )}{' '}
                            (as '{s.component_name}')
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* VIEW E: INFRASTRUCTURE & GEOLOCATION */}
      {activeSubView === 'infrastructure' && (
        <div className="space-y-6">
          {/* IP Addresses Intelligence Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Extracted IP Addresses & Geolocation Intelligence
                </h4>
                <p className="text-xs text-slate-500">
                  Shared C2 addresses, host ASNs, and multi-file sightings.
                </p>
              </div>
              <span className="text-xs font-mono text-indigo-600 font-semibold">
                {ioc_comparison.shared_ip_count} Shared IPs
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100 text-slate-600 font-mono text-[11px] border-b border-slate-200">
                    <th className="py-2.5 px-3">IP Address</th>
                    <th className="py-2.5 px-3">Country & City</th>
                    <th className="py-2.5 px-3">Autonomous System (ASN)</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Observed In Files</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono">
                  {ioc_comparison.ips.map((item, idx) => (
                    <tr key={idx} className={`hover:bg-slate-50 ${item.is_shared ? 'bg-indigo-50/30' : ''}`}>
                      <td className="py-2.5 px-3 font-bold text-slate-900">{item.ip}</td>
                      <td className="py-2.5 px-3 text-slate-700">
                        {item.country} {item.city && item.city !== 'Unknown' ? `(${item.city})` : ''}
                      </td>
                      <td className="py-2.5 px-3 text-slate-600 max-w-xs truncate" title={item.asn}>
                        {item.asn}
                      </td>
                      <td className="py-2.5 px-3">
                        {item.is_shared ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200">
                            SHARED C2 ({item.occurrences})
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-600 border border-slate-200">
                            Unique
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex flex-wrap gap-1">
                          {item.seen_in_files.map((f, fIdx) => (
                            <button
                              key={fIdx}
                              onClick={() => onSelectJob(f.job_id)}
                              className="px-1.5 py-0.2 rounded bg-slate-100 hover:bg-indigo-100 text-slate-700 hover:text-indigo-800 text-[10px] font-mono transition-colors"
                            >
                              {f.filename}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Domains & User Accounts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Domains */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="p-3.5 border-b border-slate-100 bg-slate-50">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Identified Domains ({ioc_comparison.domains.length})
                </h4>
              </div>
              <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto text-xs font-mono">
                {ioc_comparison.domains.map((d, idx) => (
                  <div key={idx} className="p-3 flex items-center justify-between hover:bg-slate-50">
                    <span className="font-bold text-slate-800 truncate max-w-xs">{d.domain}</span>
                    {d.is_shared ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200 shrink-0">
                        SHARED DOMAIN
                      </span>
                    ) : (
                      <span className="text-[10px] text-slate-400">1 file</span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Usernames & Authors */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="p-3.5 border-b border-slate-100 bg-slate-50">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  User Accounts & Document Authors ({ioc_comparison.usernames.length})
                </h4>
              </div>
              <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto text-xs font-mono">
                {ioc_comparison.usernames.map((u, idx) => (
                  <div key={idx} className="p-3 flex items-center justify-between hover:bg-slate-50">
                    <div className="flex items-center gap-2">
                      <User className="w-3.5 h-3.5 text-slate-400" />
                      <span className="font-bold text-slate-800">{u.username}</span>
                    </div>
                    {u.is_shared ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200 shrink-0">
                        SHARED ACCOUNT
                      </span>
                    ) : (
                      <span className="text-[10px] text-slate-400">1 file</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW F: CAMPAIGN MITRE ATT&CK MATRIX */}
      {activeSubView === 'mitre' && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Consolidated Cyber Kill Chain & MITRE ATT&CK Matrix
              </h4>
              <p className="text-xs text-slate-500">
                Maps attack behaviors across all {data.total_jobs} forensic artifacts into MITRE tactics.
              </p>
            </div>
            <span className="text-xs font-mono text-purple-600 font-bold">
              {mitre_campaign.total_techniques} Techniques across {mitre_campaign.active_tactics_count} Tactics
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {mitre_campaign.tactics.map((tac, idx) => (
              <div key={idx} className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                <div className="text-xs font-bold font-mono uppercase tracking-wider text-indigo-700 pb-2 border-b border-slate-200">
                  {tac.tactic} ({tac.techniques.length})
                </div>

                <div className="space-y-2">
                  {tac.techniques.map((tech, tIdx) => (
                    <div key={tIdx} className="bg-white p-2.5 rounded-lg border border-slate-200 shadow-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono font-bold text-slate-500">{tech.technique_id}</span>
                        {tech.is_shared && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-100 text-purple-800">
                            SHARED
                          </span>
                        )}
                      </div>
                      <div className="text-xs font-semibold text-slate-900 leading-tight">
                        {tech.technique_name}
                      </div>
                      <div className="pt-1 flex flex-wrap gap-1">
                        {tech.seen_in_files.map((f, fIdx) => (
                          <button
                            key={fIdx}
                            onClick={() => onSelectJob(f.job_id)}
                            className="text-[9px] font-mono bg-slate-100 hover:bg-indigo-100 text-slate-700 hover:text-indigo-800 px-1.5 py-0.5 rounded cursor-pointer transition-colors"
                            title={`Jump to ${f.filename}`}
                          >
                            {f.filename}
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW G: CROSS-ARTIFACT LINKED EVIDENCE & INCIDENT CHAIN */}
      {activeSubView === 'cross_refs' && data.cross_file_references && (
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-100 pb-4 gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-indigo-600" />
                <h4 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                  Cross-Artifact Linked References &amp; Attack Chain Navigations
                </h4>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Interactive bidirectional evidence links detected across emails, documents, scripts, executables, event logs, network captures, and archives. Click any artifact to navigate directly into its dedicated triage dashboard.
              </p>
            </div>
            <span className="text-xs font-mono text-indigo-600 font-bold px-3 py-1 bg-indigo-50 border border-indigo-200 rounded-full shrink-0">
              {data.cross_file_references.total_references} Active Reference{data.cross_file_references.total_references === 1 ? '' : 's'}
            </span>
          </div>

          {/* Table of all cross-artifact references */}
          <div className="overflow-x-auto rounded-xl border border-slate-200">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 text-slate-600 font-mono text-[11px] border-b border-slate-200">
                  <th className="py-3 px-4">Source Artifact</th>
                  <th className="py-3 px-3 text-center">Direction</th>
                  <th className="py-3 px-4">Referenced Target Artifact</th>
                  <th className="py-3 px-3">Reference Category</th>
                  <th className="py-3 px-4">Indicator / Matched Value</th>
                  <th className="py-3 px-4">Forensic Context &amp; Evidence Snippet</th>
                  <th className="py-3 px-3 text-right">Quick Navigation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {data.cross_file_references.references.map((ref, idx) => (
                  <tr key={idx} className="hover:bg-indigo-50/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-900 whitespace-nowrap">
                      <button
                        onClick={() => onSelectJob(ref.source_job_id)}
                        className="text-left font-bold text-slate-800 hover:text-indigo-600 hover:underline flex items-center gap-1.5 cursor-pointer"
                        title={`Navigate to source file: ${ref.source_filename}`}
                      >
                        <span className="truncate max-w-[160px]">{ref.source_filename}</span>
                        <ExternalLink className="w-3 h-3 text-slate-400 shrink-0" />
                      </button>
                    </td>

                    <td className="py-3 px-3 text-center text-slate-400">
                      <ArrowRight className="w-4 h-4 mx-auto text-indigo-500" />
                    </td>

                    <td className="py-3 px-4 font-semibold text-indigo-950 whitespace-nowrap">
                      <button
                        onClick={() => onSelectJob(ref.target_job_id)}
                        className="text-left font-bold text-indigo-700 hover:text-indigo-900 hover:underline flex items-center gap-1.5 cursor-pointer"
                        title={`Navigate to target file: ${ref.target_filename}`}
                      >
                        <span className="truncate max-w-[160px]">{ref.target_filename}</span>
                        <ExternalLink className="w-3 h-3 text-indigo-600 shrink-0" />
                      </button>
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-700 border border-slate-200">
                        {ref.reference_type.replace(/_/g, ' ')}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-800 font-bold max-w-xs truncate" title={ref.matched_value}>
                      {ref.matched_value}
                    </td>

                    <td className="py-3 px-4 text-slate-600 font-sans text-xs max-w-md">
                      <ReferencedText
                        text={ref.detail}
                        workspaceJobs={jobs}
                        onSelectJob={onSelectJob}
                      />
                    </td>

                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => onSelectJob(ref.target_job_id)}
                        className="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold font-sans flex items-center gap-1 cursor-pointer transition-colors shadow-2xs ml-auto"
                      >
                        <span>Open Target</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
};
