import React, { useState, useRef, useEffect, useMemo } from 'react';
import {
  Network,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ExternalLink,
  Copy,
  Check,
  Move,
  Layers,
  ArrowUpDown,
  SlidersHorizontal,
  Eye,
  EyeOff,
  CheckSquare
} from 'lucide-react';
import { EntityGraphData, EntityGraphNode } from '../types';

interface EntityGraphCardProps {
  graphData?: EntityGraphData | null;
  onSelectJob?: (jobId: string) => void;
}

const ENTITY_CATEGORIES = [
  {
    key: 'intel',
    label: 'Threat Intel',
    types: ['threat_intel', 'threat_signature'],
    color: 'bg-red-600 text-white border-red-600',
    hoverColor: 'hover:bg-red-50 hover:text-red-700'
  },
  {
    key: 'network',
    label: 'Network & Domains',
    types: ['url', 'domain', 'ip', 'geolocation', 'flow', 'protocol', 'asn', 'network', 'organization'],
    color: 'bg-sky-600 text-white border-sky-600',
    hoverColor: 'hover:bg-sky-50 hover:text-sky-700'
  },
  {
    key: 'identity',
    label: 'Identity & Users',
    types: ['user', 'auth_policy', 'tracking_pixel', 'computer', 'metadata'],
    color: 'bg-blue-600 text-white border-blue-600',
    hoverColor: 'hover:bg-blue-50 hover:text-blue-700'
  },
  {
    key: 'payloads',
    label: 'Payloads & Hashes',
    types: ['embedded_file', 'hash'],
    color: 'bg-emerald-600 text-white border-emerald-600',
    hoverColor: 'hover:bg-emerald-50 hover:text-emerald-700'
  },
  {
    key: 'ttps',
    label: 'ATT&CK TTPs',
    types: ['technique', 'similar_sample'],
    color: 'bg-rose-700 text-white border-rose-700',
    hoverColor: 'hover:bg-rose-50 hover:text-rose-700'
  },
  {
    key: 'forensics',
    label: 'Forensic Artifacts',
    types: ['log_source', 'share', 'process', 'certificate'],
    color: 'bg-purple-600 text-white border-purple-600',
    hoverColor: 'hover:bg-purple-50 hover:text-purple-700'
  }
];

const ALL_ENTITY_CATEGORY_KEYS = ENTITY_CATEGORIES.map(c => c.key);

export const EntityGraphCard: React.FC<EntityGraphCardProps> = ({ graphData, onSelectJob }) => {
  // Category Filtering
  const [selectedFilters, setSelectedFilters] = useState<string[]>(ALL_ENTITY_CATEGORY_KEYS);

  // Layout, Sorting, Spacing, Hiding
  const [layoutMode, setLayoutMode] = useState<'radial' | 'category' | 'hierarchical' | 'grid'>('radial');
  const [sortMode, setSortMode] = useState<'connectivity' | 'threat_severity' | 'alpha' | 'reverse_alpha' | 'type'>('connectivity');
  const [nodeProximity, setNodeProximity] = useState<'close' | 'middle' | 'far' | 'very_far'>('middle');
  const [hideIsolatedNodes, setHideIsolatedNodes] = useState<boolean>(false);
  const [hideBenignNodes, setHideBenignNodes] = useState<boolean>(false);
  const [showEmptyNodes, setShowEmptyNodes] = useState<boolean>(false);

  // Selection & Inspector
  const [selectedNode, setSelectedNode] = useState<EntityGraphNode | null>(null);
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(new Set());
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Viewport Zoom & Pan
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);

  // Positions & Cluster Labels
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [categoryClusterLabels, setCategoryClusterLabels] = useState<{ key: string; label: string; count: number; x: number; y: number }[]>([]);

  // Dragging mechanics (Single & Multi-Node Group Dragging)
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const nodeDragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const nodeMouseDownPosRef = useRef<{ x: number; y: number } | null>(null);
  const hasDraggedNodeRef = useRef<boolean>(false);
  const dragInitialPositionsRef = useRef<Record<string, { x: number; y: number }>>({});
  const dragOriginWorldRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Category counts for filter badges
  const categoryCounts = useMemo(() => {
    const nodes = graphData?.nodes || [];
    const nonRoot = nodes.filter(n => n.id !== 'root' && n.type !== 'root');
    const counts: Record<string, number> = {
      total: nonRoot.length
    };
    ENTITY_CATEGORIES.forEach(cat => {
      counts[cat.key] = nonRoot.filter(n => cat.types.includes(n.type)).length;
    });
    return counts;
  }, [graphData?.nodes]);

  // Only show categories that have at least 1 node in this artifact
  const availableFilterOptions = useMemo(() => {
    return ENTITY_CATEGORIES.filter(cat => (categoryCounts[cat.key] || 0) > 0).map(cat => ({
      ...cat,
      count: categoryCounts[cat.key] || 0
    }));
  }, [categoryCounts]);

  const activeCategoryKeys = useMemo(() => {
    return availableFilterOptions.map(opt => opt.key);
  }, [availableFilterOptions]);

  const isAllSelected = useMemo(() => {
    if (activeCategoryKeys.length === 0) return true;
    return activeCategoryKeys.every(k => selectedFilters.includes(k));
  }, [activeCategoryKeys, selectedFilters]);

  // Toggle "All Entities" handler matching Threat Graph
  const handleToggleAllEntities = () => {
    if (isAllSelected) {
      setSelectedFilters([]);
    } else {
      setSelectedFilters([...activeCategoryKeys]);
    }
  };

  const toggleFilter = (key: string) => {
    setSelectedFilters(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );
  };

  const handleResetFilters = () => {
    setSelectedFilters([...activeCategoryKeys]);
    setHideIsolatedNodes(false);
    setHideBenignNodes(false);
    setShowEmptyNodes(false);
  };

  // Node Degree Map for connectivity calculation & leaf filtering
  const nodeDegreeMap = useMemo(() => {
    const map: Record<string, number> = {};
    if (!graphData?.edges) return map;
    graphData.edges.forEach(e => {
      map[e.source] = (map[e.source] || 0) + 1;
      map[e.target] = (map[e.target] || 0) + 1;
    });
    return map;
  }, [graphData?.edges]);

  // Helper to identify nodes that do not contain any results or data (e.g. VirusTotal with 0 detections)
  const isEmptyNode = (node: any): boolean => {
    if (!node) return false;
    if (node.id === 'root' || node.type === 'root' || node.type === 'file') return false;

    const label = (node.label || '').toLowerCase();
    const fullLabel = (node.full_label || '').toLowerCase();
    const details = node.details || {};

    // 1. Explicit 0 detections / 0 engines / 0 results / 0 hits / 0 matches in label or full_label
    if (
      /\b0\s*(\/\s*\d+|\s*detections?|\s*results?|\s*hits?|\s*matches?|\s*findings?|\s*threats?|\s*alerts?|\s*engines?)\b/i.test(label) ||
      /\b0\s*(\/\s*\d+|\s*detections?|\s*results?|\s*hits?|\s*matches?|\s*findings?|\s*threats?|\s*alerts?|\s*engines?)\b/i.test(fullLabel)
    ) {
      return true;
    }

    // 2. VirusTotal or Threat Intel specific checks: positives === 0 or total_engines with positives === 0
    if (
      details.engine === 'VirusTotal' ||
      node.id?.includes('virustotal') ||
      node.id?.includes('intel_vt') ||
      node.type === 'threat_intel' ||
      node.type === 'threat_signature'
    ) {
      if (typeof details.positives === 'number' && details.positives === 0) return true;
      if (typeof details.threat_score === 'number' && details.threat_score === 0) return true;
      if (label.includes('0/')) return true;
      if (label.includes('(0)')) return true;
    }

    // 3. Details with explicit 0 count / hits / detections / findings / matches
    if (
      (typeof details.detections === 'number' && details.detections === 0) ||
      (typeof details.positives === 'number' && details.positives === 0) ||
      (typeof details.hits === 'number' && details.hits === 0) ||
      (typeof details.matches === 'number' && details.matches === 0) ||
      (typeof details.findings_count === 'number' && details.findings_count === 0) ||
      (typeof details.anomalies_count === 'number' && details.anomalies_count === 0) ||
      (typeof details.count === 'number' && details.count === 0)
    ) {
      return true;
    }

    // 4. "no detections", "0 detection", "0 results", "0 found", "not found"
    if (
      label.includes('no detection') ||
      label.includes('0 detection') ||
      label.includes('0 result') ||
      label.includes('0 found') ||
      label.includes('not_found') ||
      label.includes('not found') ||
      fullLabel.includes('no detection') ||
      fullLabel.includes('0 detection') ||
      fullLabel.includes('not_found') ||
      fullLabel.includes('not found')
    ) {
      return true;
    }

    // 5. Scanner or Sandbox with clean verdict / not_found
    if (
      details.verdict === 'not_found' ||
      details.verdict === 'clean' ||
      details.threat_score === 0 ||
      ((node.type === 'threat_intel' || node.type === 'threat_signature' || node.type === 'vulnerability') &&
        (node.risk === 'clean' || node.risk === 'benign') &&
        (!details.positives || details.positives === 0))
    ) {
      return true;
    }

    return false;
  };

  const emptyNodesCount = useMemo(() => {
    return (graphData?.nodes || []).filter((n: any) => isEmptyNode(n)).length;
  }, [graphData?.nodes]);

  // Multi-filtered graph nodes
  const filteredNodes = useMemo(() => {
    const nodes = graphData?.nodes || [];
    return nodes.filter(n => {
      const isRoot = n.id === 'root' || n.type === 'root' || n.type === 'file';
      if (isRoot) return true; // Always keep root file anchor

      // Hide empty nodes constraint (e.g. VirusTotal with 0 detections)
      if (!showEmptyNodes && isEmptyNode(n)) {
        return false;
      }

      // If user enabled Show Empty Nodes, guarantee empty node is shown
      if (showEmptyNodes && isEmptyNode(n)) {
        return true;
      }

      // Hide leaves (degree <= 1)
      if (hideIsolatedNodes && (nodeDegreeMap[n.id] || 0) <= 1) {
        return false;
      }

      // Hide benign
      if (hideBenignNodes) {
        const isBenign = n.risk === 'benign' || n.risk === 'info' || n.risk === 'low' || !n.risk;
        if (isBenign && !['threat_intel', 'threat_signature', 'technique'].includes(n.type)) {
          return false;
        }
      }

      // If no category filters are selected, non-root nodes are filtered out
      if (selectedFilters.length === 0) {
        return false;
      }

      // Check if node matches ANY selected category
      return selectedFilters.some(filterKey => {
        const cat = ENTITY_CATEGORIES.find(c => c.key === filterKey);
        return cat ? cat.types.includes(n.type) : false;
      });
    });
  }, [graphData?.nodes, selectedFilters, hideIsolatedNodes, hideBenignNodes, nodeDegreeMap, showEmptyNodes]);

  const visibleNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return (graphData?.edges ?? []).filter(
      e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
    );
  }, [graphData?.edges, visibleNodeIds]);

  // Select all nodes connected to a node (excluding root/file nodes), restoring filters if necessary, and close the inspector
  const handleSelectConnectedNodes = (nodeId: string) => {
    const connectedIds = new Set<string>();
    const allEdges = graphData?.edges || [];
    const allNodes = graphData?.nodes || [];
    const nodeMap = new Map<string, any>(allNodes.map((n) => [n.id, n]));

    allEdges.forEach((edge: any) => {
      let otherId: string | null = null;
      if (edge.source === nodeId) otherId = edge.target;
      else if (edge.target === nodeId) otherId = edge.source;

      if (otherId) {
        const otherNode = nodeMap.get(otherId);
        if (otherNode?.type !== 'file' && otherNode?.type !== 'root' && otherId !== 'root') {
          connectedIds.add(otherId);
        }
      }
    });

    const hasHiddenConnected = Array.from(connectedIds).some((id) => !visibleNodeIds.has(id));
    if (hasHiddenConnected) {
      setSelectedFilters([...activeCategoryKeys]);
    }

    setSelectedNodeIds(connectedIds);
    setSelectedNode(null);
  };

  // Connected node count for selectedNode (excluding root/file nodes)
  const selectedNodeConnectedCount = useMemo(() => {
    if (!selectedNode || !graphData?.edges) return 0;
    const allNodes = graphData?.nodes || [];
    const nodeMap = new Map<string, any>(allNodes.map((n) => [n.id, n]));
    const connected = new Set<string>();

    graphData.edges.forEach((edge: any) => {
      let otherId: string | null = null;
      if (edge.source === selectedNode.id) otherId = edge.target;
      else if (edge.target === selectedNode.id) otherId = edge.source;

      if (otherId) {
        const otherNode = nodeMap.get(otherId);
        if (otherNode?.type !== 'file' && otherNode?.type !== 'root' && otherId !== 'root') {
          connected.add(otherId);
        }
      }
    });
    return connected.size;
  }, [selectedNode, graphData?.edges, graphData?.nodes]);

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
        factor = Math.exp(-e.deltaY * 0.015);
      } else {
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

  // Multi-Layout & Multi-Sorting Graph Engine for Single-Artifact Entity Graph
  const calculateLayout = (
    nodes: EntityGraphNode[],
    edges: any[],
    layout: 'radial' | 'category' | 'hierarchical' | 'grid',
    sort: 'connectivity' | 'threat_severity' | 'alpha' | 'reverse_alpha' | 'type',
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

    const width = Math.max(1100, cWidth || 1200);
    const height = Math.max(600, cHeight || 620);
    const centerX = width / 2;
    const centerY = height / 2;

    const degreeMap: Record<string, number> = {};
    edges.forEach((e) => {
      degreeMap[e.source] = (degreeMap[e.source] || 0) + 1;
      degreeMap[e.target] = (degreeMap[e.target] || 0) + 1;
    });

    const getSeverityScore = (n: EntityGraphNode) => {
      if (n.risk === 'critical' || n.risk === 'malicious') return 100;
      if (n.risk === 'high') return 80;
      if (n.risk === 'warning' || n.risk === 'medium') return 60;
      if (n.type === 'technique') return 50;
      if (n.type === 'threat_intel' || n.type === 'threat_signature') return 45;
      if (n.id === 'root' || n.type === 'root') return 40;
      return 10;
    };

    const sortedNodes = [...nodes].sort((a, b) => {
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
      return 0;
    });

    const rootNode = sortedNodes.find(n => n.id === 'root' || n.type === 'root') || sortedNodes[0];
    const nonRootNodes = sortedNodes.filter(n => n.id !== rootNode.id);

    if (layout === 'radial') {
      positions[rootNode.id] = { x: centerX, y: centerY };
      const count = nonRootNodes.length;
      if (count <= 10) {
        const rad = Math.min(width * 0.42, Math.max(160 * prox, count * 36 * prox));
        nonRootNodes.forEach((node, idx) => {
          const angle = (idx / (count || 1)) * 2 * Math.PI - Math.PI / 2;
          positions[node.id] = {
            x: centerX + rad * Math.cos(angle),
            y: centerY + (rad * 0.78) * Math.sin(angle),
          };
        });
      } else {
        const innerCount = Math.ceil(count * 0.38);
        const outerCount = count - innerCount;
        const innerRad = Math.min(width * 0.28, Math.max(140 * prox, innerCount * 26 * prox));
        const outerRad = Math.min(width * 0.46, Math.max(260 * prox, outerCount * 22 * prox));

        nonRootNodes.forEach((node, idx) => {
          if (idx < innerCount) {
            const angle = (idx / innerCount) * 2 * Math.PI - Math.PI / 2;
            positions[node.id] = {
              x: centerX + innerRad * Math.cos(angle),
              y: centerY + (innerRad * 0.78) * Math.sin(angle),
            };
          } else {
            const outIdx = idx - innerCount;
            const angle = (outIdx / outerCount) * 2 * Math.PI - Math.PI / 2;
            positions[node.id] = {
              x: centerX + outerRad * Math.cos(angle),
              y: centerY + (outerRad * 0.78) * Math.sin(angle),
            };
          }
        });
      }
    } else if (layout === 'category') {
      positions[rootNode.id] = { x: centerX, y: centerY };

      const groups: Record<string, EntityGraphNode[]> = {};
      nonRootNodes.forEach((n) => {
        let catKey = 'forensics';
        for (const cat of ENTITY_CATEGORIES) {
          if (cat.types.includes(n.type)) {
            catKey = cat.key;
            break;
          }
        }
        if (!groups[catKey]) groups[catKey] = [];
        groups[catKey].push(n);
      });

      const activeGroupKeys = Object.keys(groups);
      const totalGroups = activeGroupKeys.length;

      const clusterRadiusX = Math.min(width * 0.42, Math.max(260 * prox, totalGroups * 60 * prox));
      const clusterRadiusY = Math.min(height * 0.36, Math.max(150 * prox, totalGroups * 32 * prox));

      activeGroupKeys.forEach((key, gIdx) => {
        const angle = (gIdx / (totalGroups || 1)) * 2 * Math.PI - Math.PI / 2;
        const cX = centerX + clusterRadiusX * Math.cos(angle);
        const cY = centerY + clusterRadiusY * Math.sin(angle);
        const groupNodes = groups[key];
        const gCount = groupNodes.length;

        const subRadius = Math.min(100 * prox, Math.max(45 * prox, gCount * 18 * prox));

        groupNodes.forEach((node, nIdx) => {
          if (gCount === 1) {
            positions[node.id] = { x: cX, y: cY };
          } else {
            const subAngle = (nIdx / gCount) * 2 * Math.PI;
            positions[node.id] = {
              x: cX + subRadius * Math.cos(subAngle),
              y: cY + subRadius * Math.sin(subAngle),
            };
          }
        });

        const catDef = ENTITY_CATEGORIES.find(c => c.key === key);
        const label = (catDef?.label || key).toUpperCase();
        clusterLabels.push({
          key,
          label,
          count: gCount,
          x: cX,
          y: cY - subRadius - 20,
        });
      });
    } else if (layout === 'hierarchical') {
      const tiers: EntityGraphNode[][] = [[], [], [], []];
      tiers[0].push(rootNode);

      nonRootNodes.forEach((n) => {
        if (['threat_intel', 'threat_signature', 'technique', 'similar_sample'].includes(n.type)) {
          tiers[1].push(n);
        } else if (['url', 'domain', 'ip', 'geolocation', 'asn', 'network', 'embedded_file', 'hash'].includes(n.type)) {
          tiers[2].push(n);
        } else {
          tiers[3].push(n);
        }
      });

      const tierY = [65 * prox, 200 * prox, 350 * prox, 500 * prox];
      tiers.forEach((tierNodes, tIdx) => {
        const count = tierNodes.length;
        if (count === 0) return;

        const baseSpacing = Math.min(220 * prox, Math.max(105 * prox, (width - 200) / (count || 1)));
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
      const count = sortedNodes.length;
      const cols = Math.max(3, Math.min(6, Math.ceil(Math.sqrt(count * 1.1))));
      const rows = Math.ceil(count / cols);
      const cellW = Math.round(Math.min(230, Math.max(130, (width - 140) / cols)) * prox);
      const cellH = Math.round(Math.min(150, Math.max(90, (height - 120) / rows)) * prox);
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

    // Overlap-Prevention & Collision Avoidance Relaxation Pass
    const minClearanceX = Math.round(110 * prox);
    const minClearanceY = Math.round(55 * prox);
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
            posA.x -= 20;
            posB.x += 20;
          }
        }
      }
      if (maxOverlap < 0.02) break;
    }

    return { positions, clusterLabels };
  };

  // Re-layout & redraw graph automatically when visible nodes, edges, layout mode, sort mode, or proximity changes
  useEffect(() => {
    if (filteredNodes.length > 0) {
      const { positions, clusterLabels } = calculateLayout(
        filteredNodes,
        filteredEdges,
        layoutMode,
        sortMode,
        1200,
        620,
        nodeProximity
      );
      setNodePositions(positions);
      setCategoryClusterLabels(clusterLabels);
    } else {
      setNodePositions({});
      setCategoryClusterLabels([]);
    }
  }, [filteredNodes, filteredEdges, layoutMode, sortMode, nodeProximity]);

  // Quick Select Group by Type
  const selectAllOfType = (typeKey: string) => {
    if (typeKey === 'all') {
      setSelectedNodeIds(new Set(filteredNodes.map(n => n.id)));
      return;
    }
    if (typeKey === 'none') {
      setSelectedNodeIds(new Set());
      setSelectedNode(null);
      return;
    }
    if (typeKey === 'intel') {
      setSelectedNodeIds(new Set(filteredNodes.filter(n => ['threat_intel', 'threat_signature'].includes(n.type)).map(n => n.id)));
      return;
    }
    if (typeKey === 'network') {
      setSelectedNodeIds(new Set(filteredNodes.filter(n => ['url', 'domain', 'ip', 'geolocation', 'asn', 'network', 'flow', 'protocol'].includes(n.type)).map(n => n.id)));
      return;
    }
    if (typeKey === 'payloads') {
      setSelectedNodeIds(new Set(filteredNodes.filter(n => ['embedded_file', 'hash'].includes(n.type)).map(n => n.id)));
      return;
    }
    if (typeKey === 'technique') {
      setSelectedNodeIds(new Set(filteredNodes.filter(n => ['technique', 'similar_sample'].includes(n.type)).map(n => n.id)));
      return;
    }
    if (typeKey === 'identity') {
      setSelectedNodeIds(new Set(filteredNodes.filter(n => ['user', 'computer', 'auth_policy'].includes(n.type)).map(n => n.id)));
      return;
    }
    if (typeKey === 'invert') {
      setSelectedNodeIds(prev => {
        const next = new Set<string>();
        filteredNodes.forEach(n => {
          if (!prev.has(n.id)) next.add(n.id);
        });
        return next;
      });
    }
  };

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
    if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).id === 'graph-canvas-bg') {
      setIsPanning(true);
      dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
    }
  };

  // Node Drag Handler (Supports single & multi-node simultaneous group dragging)
  const handleNodeMouseDown = (node: EntityGraphNode, e: React.MouseEvent) => {
    e.stopPropagation();
    setDraggingNodeId(node.id);
    hasDraggedNodeRef.current = false;
    nodeMouseDownPosRef.current = { x: e.clientX, y: e.clientY };

    const worldPos = clientToWorld(e.clientX, e.clientY);
    dragOriginWorldRef.current = worldPos;
    dragInitialPositionsRef.current = { ...nodePositions };

    const currNodePos = nodePositions[node.id] || { x: node.x ?? 600, y: node.y ?? 310 };
    nodeDragOffsetRef.current = {
      x: worldPos.x - currNodePos.x,
      y: worldPos.y - currNodePos.y
    };

    const isMultiSelect = e.metaKey || e.ctrlKey || e.shiftKey;
    if (!isMultiSelect && !selectedNodeIds.has(node.id)) {
      setSelectedNodeIds(new Set([node.id]));
    }
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
        setNodePositions(prev => {
          const next = { ...prev };
          selectedNodeIds.forEach(id => {
            const initPos = dragInitialPositionsRef.current[id] || prev[id];
            if (initPos) {
              next[id] = { x: Math.round((initPos.x + dx) * 10) / 10, y: Math.round((initPos.y + dy) * 10) / 10 };
            }
          });
          return next;
        });
        return;
      }

      // Single node drag
      const newX = Math.round((worldPos.x - nodeDragOffsetRef.current.x) * 10) / 10;
      const newY = Math.round((worldPos.y - nodeDragOffsetRef.current.y) * 10) / 10;
      setNodePositions(prev => ({
        ...prev,
        [draggingNodeId]: { x: newX, y: newY }
      }));
      return;
    }
    if (isPanning) {
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
    setSelectedNodeIds(new Set());
    if (filteredNodes.length > 0) {
      const { positions, clusterLabels } = calculateLayout(
        filteredNodes,
        filteredEdges,
        layoutMode,
        sortMode,
        1200,
        620,
        nodeProximity
      );
      setNodePositions(positions);
      setCategoryClusterLabels(clusterLabels);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Forensic Node Palette
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
    if (node.type === 'user' || node.type === 'auth_policy' || node.type === 'metadata') {
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

  // Unconditional render check for empty graph data
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

  return (
    <div className="bg-white border border-slate-200 rounded-3xl shadow-xs overflow-hidden flex flex-col transition-all">
      {/* Header & Main Info */}
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
              Topological entity mapping of root file, IOCs, threat intel, network targets, payload hashes, and TTPs. Grab nodes to rearrange.
            </p>
          </div>
        </div>
      </div>

      {/* Controls Toolbar Container */}
      <div className="p-4 bg-slate-50/80 border-b border-slate-200/80 flex flex-col gap-3 z-10">
        {/* Row 1: Filter Pills (Multi-Select with New "All Entities" Behavior) */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
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

            {availableFilterOptions.map((opt) => {
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

          {(!isAllSelected || hideIsolatedNodes || hideBenignNodes) && (
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
                id="entity-graph-layout-select"
                value={layoutMode}
                onChange={(e) => setLayoutMode(e.target.value as any)}
                className="bg-transparent font-medium text-slate-800 text-xs focus:outline-none cursor-pointer pr-1"
              >
                <option value="radial">Radial Orbit</option>
                <option value="category">Group by Entity Type</option>
                <option value="hierarchical">Hierarchical Tiers</option>
                <option value="grid">Structured Grid</option>
              </select>
            </div>

            {/* Sorting Mode Selector */}
            <div className="flex items-center gap-1.5 bg-white border border-slate-200 rounded-xl px-2.5 py-1.5 shadow-2xs">
              <ArrowUpDown className="w-3.5 h-3.5 text-indigo-500" />
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Sort:</span>
              <select
                id="entity-graph-sort-select"
                value={sortMode}
                onChange={(e) => setSortMode(e.target.value as any)}
                className="bg-transparent font-medium text-slate-800 text-xs focus:outline-none cursor-pointer pr-1"
              >
                <option value="connectivity">Connectivity (Degree)</option>
                <option value="threat_severity">Threat Severity & Risk</option>
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
                id="entity-graph-proximity-select"
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
                id="entity-graph-hide-isolated-btn"
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
                id="entity-graph-hide-benign-btn"
                onClick={() => setHideBenignNodes((prev) => !prev)}
                className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  hideBenignNodes
                    ? 'bg-amber-500 text-white shadow-2xs'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
                title="Hide benign & low-severity informational entities"
              >
                {hideBenignNodes ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5 text-slate-400" />}
                <span>Hide Benign</span>
              </button>
            </div>

            {/* Show Empty Nodes Filter */}
            <label
              id="entity-graph-show-empty-nodes-label"
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-all cursor-pointer select-none shadow-2xs ${
                showEmptyNodes
                  ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
                  : 'bg-white border-slate-200 text-slate-600 hover:border-slate-300'
              }`}
              title="When checked, shows nodes that do not contain any results or data (e.g. VirusTotal with 0 detections). Unchecked by default."
            >
              <input
                type="checkbox"
                id="entity-graph-show-empty-nodes"
                checked={showEmptyNodes}
                onChange={(e) => setShowEmptyNodes(e.target.checked)}
                className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer w-3.5 h-3.5"
              />
              <span>Show empty nodes</span>
              {emptyNodesCount > 0 && (
                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                  showEmptyNodes ? 'bg-indigo-200/80 text-indigo-900' : 'bg-slate-100 text-slate-500 border border-slate-200'
                }`}>
                  {emptyNodesCount}
                </span>
              )}
            </label>

            {/* Live Stats */}
            <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-slate-100/90 text-[11px] font-medium text-slate-600 border border-slate-200 font-mono">
              <span><strong className="text-slate-900">{filteredNodes.length}</strong> / {graphData.nodes.length} nodes</span>
              <span className="text-slate-300">•</span>
              <span><strong className="text-slate-900">{filteredEdges.length}</strong> lines</span>
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
                onClick={() => setZoom((z) => Math.min(3.5, z + 0.2))}
                className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
                title="Zoom In"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                onClick={() => setZoom((z) => Math.max(0.3, z - 0.2))}
                className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
                title="Zoom Out"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                onClick={handleResetView}
                className="p-1.5 hover:bg-slate-100 rounded-lg text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
                title="Reset View & Layout"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Row 3: Quick Select Group & Multi-Node Movement Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 pt-2.5 border-t border-slate-200/60 text-xs">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mr-1 flex items-center gap-1">
              <CheckSquare className="w-3.5 h-3.5 text-indigo-500" />
              <span>Select Group:</span>
            </span>

            <button
              type="button"
              onClick={() => selectAllOfType('all')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors cursor-pointer shadow-2xs"
            >
              All
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('intel')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-red-50 text-red-700 border border-slate-200 hover:border-red-300 transition-colors cursor-pointer shadow-2xs"
            >
              Intel
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('network')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-sky-50 text-sky-700 border border-slate-200 hover:border-sky-300 transition-colors cursor-pointer shadow-2xs"
            >
              Network
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('payloads')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-emerald-50 text-emerald-700 border border-slate-200 hover:border-emerald-300 transition-colors cursor-pointer shadow-2xs"
            >
              Payloads
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('technique')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-rose-50 text-rose-700 border border-slate-200 hover:border-rose-300 transition-colors cursor-pointer shadow-2xs"
            >
              TTPs
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('identity')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-blue-50 text-blue-700 border border-slate-200 hover:border-blue-300 transition-colors cursor-pointer shadow-2xs"
            >
              Identity
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('invert')}
              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-white hover:bg-indigo-50 text-indigo-700 border border-slate-200 hover:border-indigo-300 transition-colors cursor-pointer shadow-2xs"
            >
              Invert
            </button>
            <button
              type="button"
              onClick={() => selectAllOfType('none')}
              className="px-2.5 py-1 rounded-lg text-xs font-medium text-slate-500 hover:text-slate-700 transition-colors cursor-pointer ml-1"
            >
              Clear
            </button>
          </div>

          {selectedNodeIds.size > 0 && (
            <div className="flex items-center gap-2 text-indigo-700 font-semibold bg-indigo-50 px-2.5 py-1 rounded-lg border border-indigo-200">
              <span className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse" />
              <span>{selectedNodeIds.size} node{selectedNodeIds.size > 1 ? 's' : ''} selected — drag to move group</span>
            </div>
          )}
        </div>
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
            {/* Category Cluster Labels when in Category Layout Mode */}
            {layoutMode === 'category' &&
              categoryClusterLabels.map((cl) => (
                <g key={`cluster-${cl.key}`} transform={`translate(${cl.x}, ${cl.y})`} className="pointer-events-none select-none">
                  <rect
                    x={-(cl.label.length * 4.2 + 20)}
                    y="-14"
                    width={cl.label.length * 8.4 + 40}
                    height="24"
                    rx="12"
                    fill="#ffffff"
                    stroke="#cbd5e1"
                    strokeWidth="1.2"
                    className="filter drop-shadow-xs"
                    opacity="0.96"
                  />
                  <text
                    y="3"
                    textAnchor="middle"
                    fill="#475569"
                    fontSize="10"
                    fontWeight="700"
                    fontFamily="ui-sans-serif, system-ui, sans-serif"
                    letterSpacing="0.05em"
                  >
                    {cl.label} ({cl.count})
                  </text>
                </g>
              ))}

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
              const isInspectorSelected = selectedNode?.id === node.id;
              const isSelectedInGroup = selectedNodeIds.has(node.id);
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
                      const isMultiSelect = e.metaKey || e.ctrlKey || e.shiftKey;
                      if (isMultiSelect) {
                        setSelectedNodeIds(prev => {
                          const next = new Set(prev);
                          if (next.has(node.id)) {
                            next.delete(node.id);
                            if (selectedNode?.id === node.id) {
                              setSelectedNode(null);
                            }
                          } else {
                            next.add(node.id);
                            setSelectedNode(node);
                          }
                          return next;
                        });
                      } else {
                        setSelectedNode(prev => prev?.id === node.id ? null : node);
                        setSelectedNodeIds(new Set([node.id]));
                      }
                    }
                  }}
                  onMouseEnter={() => setHoveredNodeId(node.id)}
                  onMouseLeave={() => setHoveredNodeId(null)}
                  className="cursor-pointer"
                >
                  {/* Multi-selection Halo */}
                  {isSelectedInGroup && (
                    <circle
                      r={radius + 7}
                      fill="none"
                      stroke="#6366f1"
                      strokeWidth={2.5}
                      strokeDasharray="4 2"
                      opacity="0.9"
                    />
                  )}

                  {/* Inspector / Hover Halo */}
                  {(isInspectorSelected || isHovered) && !isSelectedInGroup && (
                    <circle
                      r={radius + 6}
                      fill="none"
                      stroke={isInspectorSelected ? '#6366f1' : styling.stroke}
                      strokeWidth={isInspectorSelected ? 2.5 : 1.5}
                      opacity={isInspectorSelected ? '0.9' : '0.6'}
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
                      : node.type === 'metadata'
                      ? 'META'
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
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => handleSelectConnectedNodes(selectedNode.id)}
                  className="p-1.5 text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded-xl transition-colors cursor-pointer"
                  title="Select connected nodes & close inspector"
                >
                  <Network className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-slate-700 p-1.5 hover:bg-slate-100 rounded-xl transition-colors cursor-pointer"
                  title="Close Details"
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Select Connected Nodes Action Button */}
            <button
              type="button"
              onClick={() => handleSelectConnectedNodes(selectedNode.id)}
              className="w-full mt-3 py-2 px-3 rounded-xl bg-indigo-50 hover:bg-indigo-100 active:bg-indigo-200 text-indigo-700 border border-indigo-200 text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-2xs group"
              title="Close inspector and select all connected nodes in graph"
            >
              <Network className="w-3.5 h-3.5 text-indigo-600 group-hover:scale-110 transition-transform" />
              <span>Select Connected Nodes</span>
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded-md bg-indigo-200/80 text-indigo-800">
                {selectedNodeConnectedCount}
              </span>
            </button>

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
