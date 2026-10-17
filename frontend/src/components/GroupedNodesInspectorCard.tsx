import React, { useState, useMemo } from 'react';
import {
  Layers,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Search,
  CornerDownRight,
  GitBranch,
  ArrowRight,
  Globe,
  Radio,
  FileCode,
  Server
} from 'lucide-react';
import { EntityGraphNode } from '../types';

interface GroupedNodesInspectorCardProps {
  node: EntityGraphNode | any;
  allNodes?: (EntityGraphNode | any)[];
  onSelectNode?: (node: any) => void;
  copiedKey: string | null;
  onCopy: (text: string, key: string) => void;
}

export const GroupedNodesInspectorCard: React.FC<GroupedNodesInspectorCardProps> = ({
  node,
  allNodes = [],
  onSelectNode,
  copiedKey,
  onCopy,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedMemberIds, setExpandedMemberIds] = useState<Set<string>>(new Set());
  const [expandAll, setExpandAll] = useState(false);

  const groupedNodes: any[] = useMemo(() => {
    if (Array.isArray(node.groupedNodes) && node.groupedNodes.length > 0) {
      return node.groupedNodes;
    }
    // Fallback to groupedVariants if groupedNodes not populated
    if (Array.isArray(node.groupedVariants) && node.groupedVariants.length > 0) {
      return node.groupedVariants.map((v: string, i: number) => ({
        id: `${node.id}_var_${i}`,
        label: v,
        full_label: v,
        type: node.type,
        risk: node.risk,
        details: node.details || {},
      }));
    }
    return [];
  }, [node]);

  if (!node.groupedCount || node.groupedCount <= 1 || groupedNodes.length === 0) {
    return null;
  }

  const filteredMembers = useMemo(() => {
    if (!searchTerm.trim()) return groupedNodes;
    const q = searchTerm.toLowerCase();
    return groupedNodes.filter((m) => {
      const label = (m.full_label || m.label || m.id || '').toLowerCase();
      const type = (m.type || '').toLowerCase();
      const detailsStr = JSON.stringify(m.details || {}).toLowerCase();
      return label.includes(q) || type.includes(q) || detailsStr.includes(q);
    });
  }, [groupedNodes, searchTerm]);

  const toggleExpand = (id: string) => {
    setExpandedMemberIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleToggleExpandAll = () => {
    if (expandAll) {
      setExpandedMemberIds(new Set());
      setExpandAll(false);
    } else {
      setExpandedMemberIds(new Set(groupedNodes.map((m) => m.id)));
      setExpandAll(true);
    }
  };

  const getRiskBadgeClass = (risk?: string) => {
    switch ((risk || '').toLowerCase()) {
      case 'critical':
        return 'bg-rose-100 text-rose-700 border-rose-200';
      case 'high':
        return 'bg-red-100 text-red-700 border-red-200';
      case 'warning':
      case 'medium':
        return 'bg-amber-100 text-amber-700 border-amber-200';
      case 'low':
        return 'bg-blue-100 text-blue-700 border-blue-200';
      case 'clean':
      case 'info':
      default:
        return 'bg-emerald-100 text-emerald-700 border-emerald-200';
    }
  };

  const getTypeIcon = (type: string) => {
    switch ((type || '').toLowerCase()) {
      case 'url':
        return <Globe className="w-3 h-3 text-sky-600" />;
      case 'domain':
      case 'hostname':
        return <Server className="w-3 h-3 text-indigo-600" />;
      case 'ip':
        return <Radio className="w-3 h-3 text-amber-600" />;
      default:
        return <FileCode className="w-3 h-3 text-slate-500" />;
    }
  };

  return (
    <div className="p-3 bg-indigo-50/70 border border-indigo-200/90 rounded-2xl space-y-2.5 shadow-2xs">
      {/* Header */}
      <div className="flex items-center justify-between text-indigo-950 font-bold text-xs">
        <span className="flex items-center gap-1.5">
          <Layers className="w-4 h-4 text-indigo-600" />
          <span>Consolidated Group Data</span>
        </span>
        <div className="flex items-center gap-1.5">
          <span className="px-2 py-0.5 rounded-full bg-indigo-200/80 text-indigo-800 text-[10px] font-mono font-semibold">
            {groupedNodes.length} Member Nodes
          </span>
          <button
            type="button"
            onClick={handleToggleExpandAll}
            className="text-[10px] text-indigo-600 hover:text-indigo-800 underline font-medium cursor-pointer"
          >
            {expandAll ? 'Collapse All' : 'Expand All'}
          </button>
        </div>
      </div>

      <p className="text-[11px] text-indigo-800/90 leading-snug">
        These {groupedNodes.length} indicators share semantic identity and are consolidated into this entity.
        Click any member below to inspect its individual forensic attributes and telemetry:
      </p>

      {/* Filter search box when more than 3 members */}
      {groupedNodes.length > 3 && (
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Filter member indicators & metadata..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-8 pr-2.5 py-1 text-[11px] bg-white border border-indigo-200 rounded-lg text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
      )}

      {/* Member Cards List */}
      <div className="space-y-1.5 max-h-72 overflow-y-auto pr-0.5">
        {filteredMembers.map((member: any, idx: number) => {
          const mId = member.id || `member_${idx}`;
          const isExpanded = expandAll || expandedMemberIds.has(mId);
          const fullLabel = member.full_label || member.label || mId;
          const memberDetails = member.details || {};
          const detailEntries = Object.entries(memberDetails).filter(
            ([_, v]) => v !== null && v !== undefined && v !== '' && typeof v !== 'function'
          );

          return (
            <div
              key={mId}
              className="bg-white/95 rounded-xl border border-indigo-100/90 shadow-2xs overflow-hidden transition-all text-xs"
            >
              {/* Card Header */}
              <div
                onClick={() => toggleExpand(mId)}
                className="px-2.5 py-2 flex items-center justify-between gap-2 cursor-pointer hover:bg-indigo-50/40 select-none"
              >
                <div className="flex items-center gap-1.5 min-w-0 flex-1">
                  <span className="text-slate-400 hover:text-slate-600 shrink-0">
                    {isExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-indigo-600" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5" />
                    )}
                  </span>
                  <span className="shrink-0">{getTypeIcon(member.type)}</span>
                  <span
                    className="font-mono text-[11px] text-slate-800 font-semibold truncate"
                    title={fullLabel}
                  >
                    {fullLabel}
                  </span>
                </div>

                <div className="flex items-center gap-1 shrink-0">
                  <span
                    className={`px-1.5 py-0.2 rounded-md text-[9.5px] font-bold border uppercase ${getRiskBadgeClass(
                      member.risk
                    )}`}
                  >
                    {member.risk || 'clean'}
                  </span>
                  <span className="px-1.5 py-0.2 rounded-md bg-slate-100 text-slate-600 border border-slate-200 text-[9.5px] font-mono uppercase">
                    {member.type}
                  </span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onCopy(fullLabel, `group_mem_${mId}`);
                    }}
                    className="p-1 rounded text-slate-400 hover:text-indigo-600 shrink-0 cursor-pointer"
                    title="Copy full indicator"
                  >
                    {copiedKey === `group_mem_${mId}` ? (
                      <Check className="w-3 h-3 text-emerald-600" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </div>
              </div>

              {/* Expanded Data Attributes */}
              {isExpanded && (
                <div className="px-2.5 pb-2.5 pt-1 border-t border-indigo-50/80 bg-slate-50/40 space-y-1.5">
                  {/* Full Raw Value */}
                  <div className="space-y-0.5">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                      Exact Indicator String
                    </span>
                    <div className="p-1.5 bg-white rounded-lg border border-slate-200 text-[10.5px] font-mono text-slate-800 break-all select-all flex items-center justify-between gap-1.5">
                      <span>{fullLabel}</span>
                      <button
                        type="button"
                        onClick={() => onCopy(fullLabel, `raw_${mId}`)}
                        className="text-slate-400 hover:text-indigo-600 shrink-0 cursor-pointer"
                        title="Copy string"
                      >
                        {copiedKey === `raw_${mId}` ? (
                          <Check className="w-3 h-3 text-emerald-600" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Attributes Grid */}
                  {detailEntries.length > 0 ? (
                    <div className="space-y-1 pt-1">
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                        Technical Metadata & Details
                      </span>
                      <div className="grid grid-cols-1 gap-1">
                        {detailEntries.map(([k, v]) => {
                          const valStr =
                            typeof v === 'object' && v !== null
                              ? JSON.stringify(v)
                              : String(v);
                          const isCopyable =
                            k.toLowerCase().includes('ip') ||
                            k.toLowerCase().includes('url') ||
                            k.toLowerCase().includes('hash') ||
                            k === 'domain';

                          return (
                            <div
                              key={k}
                              className="px-2 py-1 bg-white rounded-lg border border-slate-200/80 flex items-start justify-between gap-2 text-[10.5px]"
                            >
                              <span className="font-semibold text-slate-600 capitalize shrink-0 pt-0.5">
                                {k.replace(/_/g, ' ')}:
                              </span>
                              <div className="flex items-center gap-1.5 font-mono text-slate-800 break-all text-right select-all flex-1 justify-end">
                                <span>{valStr}</span>
                                {isCopyable && (
                                  <button
                                    type="button"
                                    onClick={() => onCopy(valStr, `${mId}_${k}`)}
                                    className="text-slate-400 hover:text-indigo-600 shrink-0 cursor-pointer"
                                    title={`Copy ${k}`}
                                  >
                                    {copiedKey === `${mId}_${k}` ? (
                                      <Check className="w-2.5 h-2.5 text-emerald-600" />
                                    ) : (
                                      <Copy className="w-2.5 h-2.5" />
                                    )}
                                  </button>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ) : (
                    <p className="text-[10px] text-slate-400 italic">No additional metadata attributes recorded.</p>
                  )}

                  {/* Jump / Inspect Action */}
                  {onSelectNode && member.id && (
                    <div className="pt-1 flex justify-end">
                      <button
                        type="button"
                        onClick={() => {
                          const targetNode = allNodes.find((n) => n.id === member.id) || member;
                          onSelectNode(targetNode);
                        }}
                        className="px-2 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-md font-semibold text-[10px] flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        <span>Focus this indicator</span>
                        <ArrowRight className="w-2.5 h-2.5" />
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

interface HierarchyInspectorCardProps {
  node: EntityGraphNode | any;
  allNodes?: (EntityGraphNode | any)[];
  onSelectNode?: (node: any) => void;
  copiedKey: string | null;
  onCopy: (text: string, key: string) => void;
}

export const HierarchyInspectorCard: React.FC<HierarchyInspectorCardProps> = ({
  node,
  allNodes = [],
  onSelectNode,
  copiedKey,
  onCopy,
}) => {
  const hasParent = Boolean(node.isChild || node.parentId);
  const childNodes: any[] = useMemo(() => {
    if (Array.isArray(node.childNodes) && node.childNodes.length > 0) {
      return node.childNodes;
    }
    if (Array.isArray(node.childIds) && node.childIds.length > 0 && allNodes.length > 0) {
      const cIdSet = new Set(node.childIds);
      return allNodes.filter((n) => cIdSet.has(n.id));
    }
    return [];
  }, [node, allNodes]);

  const hasChildren = childNodes.length > 0 || (node.childrenCount && node.childrenCount > 0);

  if (!hasParent && !hasChildren) {
    return null;
  }

  const parentNode = useMemo(() => {
    if (!node.parentId || allNodes.length === 0) return null;
    return allNodes.find((n) => n.id === node.parentId);
  }, [node.parentId, allNodes]);

  const getRelationBadge = (rel?: string) => {
    switch (rel) {
      case 'child_endpoint':
        return 'Child Endpoint / Path';
      case 'subdomain':
        return 'Subdomain';
      case 'service_port':
        return 'Service Port';
      case 'embedded_content':
        return 'Embedded Payload';
      case 'child_process':
        return 'Child Process';
      default:
        return rel || 'Subordinate Entity';
    }
  };

  const getRiskBadgeClass = (risk?: string) => {
    switch ((risk || '').toLowerCase()) {
      case 'critical':
        return 'bg-rose-100 text-rose-700 border-rose-200';
      case 'high':
        return 'bg-red-100 text-red-700 border-red-200';
      case 'warning':
      case 'medium':
        return 'bg-amber-100 text-amber-700 border-amber-200';
      case 'low':
        return 'bg-blue-100 text-blue-700 border-blue-200';
      default:
        return 'bg-emerald-100 text-emerald-700 border-emerald-200';
    }
  };

  return (
    <div className="space-y-2">
      {/* Parent Entity Banner (When node is a child item) */}
      {hasParent && (
        <div className="p-3 bg-amber-50/80 border border-amber-200 rounded-2xl space-y-2 shadow-2xs">
          <div className="flex items-center justify-between text-amber-950 font-bold text-xs">
            <span className="flex items-center gap-1.5">
              <CornerDownRight className="w-3.5 h-3.5 text-amber-600" />
              <span>Parent Entity</span>
            </span>
            <span className="px-2 py-0.5 rounded-full bg-amber-200/80 text-amber-800 text-[9.5px] font-semibold">
              {getRelationBadge(node.hierarchyRelation)}
            </span>
          </div>

          <div className="bg-white/90 p-2.5 rounded-xl border border-amber-100 flex items-center justify-between gap-2">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span className="px-1.5 py-0.2 rounded-md bg-slate-100 text-slate-700 border border-slate-200 text-[9px] font-mono uppercase font-bold">
                  {node.parentType || parentNode?.type || 'Entity'}
                </span>
                <span className="font-mono text-xs font-bold text-slate-900 truncate">
                  {node.parentLabel || parentNode?.full_label || parentNode?.label || node.parentId}
                </span>
              </div>
              <p className="text-[10px] text-slate-500 mt-0.5">
                This entity is a subordinate child item under this parent container.
              </p>
            </div>

            {onSelectNode && (parentNode || node.parentId) && (
              <button
                type="button"
                onClick={() => {
                  if (parentNode) onSelectNode(parentNode);
                  else if (node.parentId) onSelectNode({ id: node.parentId, label: node.parentLabel });
                }}
                className="px-2.5 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg font-semibold text-[11px] flex items-center gap-1 shrink-0 transition-colors shadow-2xs cursor-pointer"
              >
                <span>Jump to Parent</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      )}

      {/* Child Entities Tree Section (When node is a parent of subordinate items) */}
      {hasChildren && (
        <div className="p-3 bg-emerald-50/70 border border-emerald-200/90 rounded-2xl space-y-2 shadow-2xs">
          <div className="flex items-center justify-between text-emerald-950 font-bold text-xs">
            <span className="flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-emerald-600" />
              <span>Subordinate Child Entities</span>
            </span>
            <span className="px-2 py-0.5 rounded-full bg-emerald-200/80 text-emerald-800 text-[10px] font-mono font-bold">
              {node.childrenCount || childNodes.length} Children
            </span>
          </div>

          <p className="text-[11px] text-emerald-800 leading-snug">
            Entities hierarchically rooted under this node (e.g. child URLs, subdomains, or port services):
          </p>

          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-0.5">
            {childNodes.map((child: any, cIdx: number) => {
              const childLabel = child.full_label || child.label || child.id || `Child ${cIdx + 1}`;
              return (
                <div
                  key={child.id || cIdx}
                  className="bg-white/95 p-2 rounded-xl border border-emerald-100 flex items-center justify-between gap-2 shadow-2xs text-xs"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="px-1.5 py-0.2 rounded-md bg-slate-100 text-slate-700 border border-slate-200 text-[9px] font-mono uppercase font-bold">
                        {child.type}
                      </span>
                      <span
                        className="font-mono text-[11px] font-semibold text-slate-800 truncate"
                        title={childLabel}
                      >
                        {childLabel}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <span
                      className={`px-1.5 py-0.2 rounded-md text-[9px] font-bold border uppercase ${getRiskBadgeClass(
                        child.risk
                      )}`}
                    >
                      {child.risk || 'clean'}
                    </span>
                    <button
                      type="button"
                      onClick={() => onCopy(childLabel, `child_copy_${child.id}`)}
                      className="p-1 rounded text-slate-400 hover:text-emerald-700 cursor-pointer"
                      title="Copy indicator"
                    >
                      {copiedKey === `child_copy_${child.id}` ? (
                        <Check className="w-3 h-3 text-emerald-600" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                    {onSelectNode && (
                      <button
                        type="button"
                        onClick={() => onSelectNode(child)}
                        className="px-2 py-1 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md font-semibold text-[10px] flex items-center gap-1 transition-colors cursor-pointer shadow-2xs"
                      >
                        <span>Inspect</span>
                        <ArrowRight className="w-2.5 h-2.5" />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
