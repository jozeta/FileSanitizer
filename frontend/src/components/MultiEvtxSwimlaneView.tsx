import React, { useState, useMemo, useRef } from 'react';
import {
  Server,
  Shield,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Search,
  Download,
  ExternalLink,
  User,
  Terminal,
  Check,
  Copy,
  X,
  Zap,
  SlidersHorizontal,
  Flame,
  FileCode,
  Cpu,
  Network,
  Globe,
  CheckCircle2
} from 'lucide-react';
import { WorkspaceJob } from '../types';
import { getEventName } from '../utils/knownEvtxEvents';
import { findReferencedJob } from '../utils/crossFileReferences';
import { ReferencedText } from './ReferencedFileLink';

interface MultiEvtxSwimlaneViewProps {
  jobs: WorkspaceJob[];
  correlationEvents?: any[];
  lateralChains?: any[];
  onSelectJob: (jobId: string) => void;
  onSwitchToTable?: () => void;
}

interface SwimlaneHost {
  jobId: string;
  filename: string;
  computer: string;
  channel: string;
  totalEvents: number;
  threatEventsCount: number;
  events: NormalizedEvtxEvent[];
}

interface NormalizedEvtxEvent {
  id: string;
  jobId: string;
  filename: string;
  computer: string;
  eventId: number;
  eventName: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  timestamp: string;
  epoch: number;
  user: string;
  ipAddress?: string;
  processName?: string;
  commandLine?: string;
  serviceName?: string;
  summary: string;
  description: string;
  details: Record<string, any>;
  isThreat: boolean;
  threatReason?: string;
  isAnomaly: boolean;
  logonType?: string;
}

interface SynchronizedTimeRow {
  epoch: number;
  timeLabel: string;
  dateLabel: string;
  relativeSeconds: number;
  eventsByHost: Record<string, NormalizedEvtxEvent[]>;
  isCrossHostInteraction: boolean;
  crossHostNotes?: string;
}

export const MultiEvtxSwimlaneView: React.FC<MultiEvtxSwimlaneViewProps> = ({
  jobs,
  correlationEvents = [],
  lateralChains = [],
  onSelectJob,
  onSwitchToTable,
}) => {
  // Search & filter states
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'threats' | 'critical'>('all');
  const [selectedEventId, setSelectedEventId] = useState<string>('all');
  const [densityMode, setDensityMode] = useState<'comfortable' | 'compact'>('comfortable');
  const [selectedEventForModal, setSelectedEventForModal] = useState<NormalizedEvtxEvent | null>(null);
  const [copiedState, setCopiedState] = useState<boolean>(false);

  // Active highlighted row for crosshairs
  const [hoveredEpoch, setHoveredEpoch] = useState<number | null>(null);

  const timelineContainerRef = useRef<HTMLDivElement | null>(null);

  // 1. Identify EVTX Jobs and Build Normalized Host Swimlanes
  const hosts: SwimlaneHost[] = useMemo(() => {
    const evtxList = (jobs || []).filter((j: any) => {
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

    return evtxList.map((job: any, idx) => {
      const jobId: string = job.jobId || job.job_id || `job_${idx}`;
      const filename: string = job.original_filename || job.filename || `sample_${idx}.evtx`;
      const info = job.evtx_info || (job.analysis_data && job.analysis_data.evtx) || {};
      const rawEvents: any[] =
        info.timeline ||
        info.timeline_events ||
        info.events ||
        info.records ||
        [];

      // Fallback: match from correlationEvents if raw timeline is empty
      const eventsSource = rawEvents.length > 0
        ? rawEvents
        : (correlationEvents || []).filter((e: any) => e.job_id === jobId || e.jobId === jobId || e.filename === filename);

      // Determine primary computer
      const computers = eventsSource.map((e: any) => e.computer).filter(Boolean);
      const primaryComputer = computers.length > 0
        ? computers.sort((a: any, b: any) => computers.filter((v: any) => v === a).length - computers.filter((v: any) => v === b).length).pop()
        : filename;

      const channels = eventsSource.map((e: any) => e.channel).filter(Boolean);
      const primaryChannel = channels.length > 0 ? channels[0] : 'Security';

      // Normalize events
      const normalizedList: NormalizedEvtxEvent[] = eventsSource.map((e: any, eIdx: number) => {
        let eid = Number(e.event_id || e.EventID || 0);
        if (!eid || isNaN(eid)) {
          const match =
            (e.event || '').match(/Event\s+(\d+)/i) ||
            (e.description || '').match(/Event\s+(\d+)/i) ||
            (e.title || '').match(/Event\s+(\d+)/i) ||
            (e.event || '').match(/\b(4624|4625|4688|4104|7045|4672|4720|4728|4732|4756|5140|5145|1102|104|5001|4616|4698|4697|22|11|1|3|7|10)\b/);
          if (match) {
            eid = Number(match[1]);
          } else if (e.event_type === 'EVTX_USER_LOGON' || (e.event || '').toLowerCase().includes('logon')) {
            eid = 4624;
          } else if (e.event_type === 'EVTX_PROCESS_CREATION' || (e.event || '').toLowerCase().includes('process created')) {
            eid = 4688;
          } else if (e.event_type === 'EVTX_SERVICE_INSTALLED' || (e.event || '').toLowerCase().includes('service installed')) {
            eid = 7045;
          } else if (e.event_type === 'EVTX_AUDIT_LOG_CLEARED' || (e.event || '').toLowerCase().includes('log cleared')) {
            eid = 1102;
          }
        }
        const knownName = eid > 0 ? getEventName(eid) : '';
        const name = e.event || e.event_name || (knownName && !knownName.startsWith('Event ID') ? `${knownName} (${eid})` : '') || (eid > 0 ? `Event ${eid}` : 'Security Event');
        const sev = (e.severity || (e.is_threat ? 'high' : 'info')).toLowerCase() as any;
        const ts = e.timestamp || e.time_created || e.iso_timestamp || new Date().toISOString();
        const ep = new Date(ts).getTime() || 0;

        return {
          id: `${jobId}_${eIdx}_${eid}`,
          jobId: jobId,
          filename: filename,
          computer: e.computer || primaryComputer,
          eventId: eid,
          eventName: name,
          category: e.category || 'Security Event',
          severity: ['critical', 'high', 'medium', 'low', 'info'].includes(sev) ? sev : 'info',
          timestamp: ts,
          epoch: ep,
          user: e.user || e.TargetUserName || e.target_user_name || '-',
          ipAddress: e.ip_address || e.ip || e.IpAddress,
          processName: e.process_name || e.NewProcessName || e.Image,
          commandLine: e.command_line || e.CommandLine || e.script_text,
          serviceName: e.service_name || e.ServiceName,
          summary: e.summary || e.event || name,
          description: e.description || e.summary || '',
          details: e.details || {},
          isThreat: Boolean(e.is_threat || e.is_anomaly || ['critical', 'high'].includes(sev)),
          threatReason: e.threat_reason,
          isAnomaly: Boolean(e.is_anomaly),
          logonType: e.logon_type || e.details?.LogonType,
        };
      });

      // Sort host events strictly by timestamp
      normalizedList.sort((a, b) => a.epoch - b.epoch);

      const threatCount = normalizedList.filter((e) => e.isThreat || e.isAnomaly || ['critical', 'high'].includes(e.severity)).length;

      return {
        jobId: jobId,
        filename: filename,
        computer: primaryComputer,
        channel: primaryChannel,
        totalEvents: normalizedList.length,
        threatEventsCount: threatCount,
        events: normalizedList,
      };
    });
  }, [jobs, correlationEvents]);

  // 2. Build Synchronized Time Rows Across All Hosts
  const timeRows: SynchronizedTimeRow[] = useMemo(() => {
    if (hosts.length === 0) return [];

    // Collect all unique epoch seconds across all hosts
    const epochMap: Map<number, { ts: string; relativeSeconds: number }> = new Map();
    let minEpoch = Infinity;

    hosts.forEach((h) => {
      h.events.forEach((ev) => {
        if (ev.epoch > 0 && ev.epoch < minEpoch) {
          minEpoch = ev.epoch;
        }
      });
    });

    if (minEpoch === Infinity) minEpoch = 0;

    // Second-precision bucket
    hosts.forEach((h) => {
      h.events.forEach((ev) => {
        const secEpoch = Math.floor(ev.epoch / 1000) * 1000;
        if (!epochMap.has(secEpoch)) {
          const relSec = Math.max(0, Math.floor((secEpoch - minEpoch) / 1000));
          epochMap.set(secEpoch, {
            ts: ev.timestamp,
            relativeSeconds: relSec,
          });
        }
      });
    });

    // Sort distinct epoch moments ascending
    const sortedEpochs = Array.from(epochMap.keys()).sort((a, b) => a - b);

    // Build row objects with eventsByHost
    return sortedEpochs.map((epoch) => {
      const meta = epochMap.get(epoch)!;
      const d = new Date(epoch);
      const timeLabel = isNaN(d.getTime())
        ? 'Time N/A'
        : d.toISOString().substring(11, 19) + ' UTC';
      const dateLabel = isNaN(d.getTime())
        ? ''
        : d.toISOString().substring(0, 10);

      const eventsByHost: Record<string, NormalizedEvtxEvent[]> = {};
      let hostCountWithEvents = 0;

      hosts.forEach((h) => {
        const matching = h.events.filter((ev) => {
          const evSec = Math.floor(ev.epoch / 1000) * 1000;
          return evSec === epoch;
        });
        eventsByHost[h.jobId] = matching;
        if (matching.length > 0) hostCountWithEvents++;
      });

      // Detect cross-host interactions in this second
      let isCrossHost = hostCountWithEvents > 1;
      let notes = '';

      if (isCrossHost) {
        const participatingComputers = hosts
          .filter((h) => (eventsByHost[h.jobId] || []).length > 0)
          .map((h) => h.computer);
        notes = participatingComputers.join(' ↔ ');
      }

      // Check for lateral movement patterns
      hosts.forEach((h) => {
        (eventsByHost[h.jobId] || []).forEach((ev) => {
          if (ev.eventId === 4624 && String(ev.logonType) === '3') {
            isCrossHost = true;
            notes = `Network Logon (Type 3) to ${ev.computer}`;
          } else if (ev.eventId === 7045 && ev.serviceName?.toLowerCase().includes('psexec')) {
            isCrossHost = true;
            notes = `PsExec Remote Execution on ${ev.computer}`;
          } else if (ev.eventId === 4648) {
            isCrossHost = true;
            notes = `Explicit Credential Logon from ${ev.computer}`;
          }
        });
      });

      return {
        epoch,
        timeLabel,
        dateLabel,
        relativeSeconds: meta.relativeSeconds,
        eventsByHost,
        isCrossHostInteraction: isCrossHost,
        crossHostNotes: notes,
      };
    });
  }, [hosts]);

  // Unique Event IDs across all hosts for filter chip dropdown
  const uniqueEventIds = useMemo(() => {
    const set = new Set<number>();
    hosts.forEach((h) => {
      h.events.forEach((ev) => {
        if (ev.eventId > 0) set.add(ev.eventId);
      });
    });
    return Array.from(set).sort((a, b) => a - b);
  }, [hosts]);

  // Filtered Time Rows based on Search & Active Filters
  const filteredTimeRows = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();

    return timeRows
      .map((row) => {
        const filteredEventsByHost: Record<string, NormalizedEvtxEvent[]> = {};
        let rowHasMatch = false;

        hosts.forEach((h) => {
          const list = row.eventsByHost[h.jobId] || [];
          const filteredList = list.filter((ev) => {
            // Severity filter
            if (severityFilter === 'threats' && !ev.isThreat && !ev.isAnomaly && !['critical', 'high'].includes(ev.severity)) {
              return false;
            }
            if (severityFilter === 'critical' && ev.severity !== 'critical' && !ev.isAnomaly) {
              return false;
            }

            // Event ID filter
            if (selectedEventId !== 'all' && String(ev.eventId) !== selectedEventId) {
              return false;
            }

            // Search query filter
            if (q) {
              const combined = `${ev.eventName} ${ev.eventId} ${ev.user} ${ev.ipAddress || ''} ${ev.processName || ''} ${ev.commandLine || ''} ${ev.summary} ${ev.description} ${ev.computer}`.toLowerCase();
              if (!combined.includes(q)) {
                return false;
              }
            }

            return true;
          });

          filteredEventsByHost[h.jobId] = filteredList;
          if (filteredList.length > 0) {
            rowHasMatch = true;
          }
        });

        if (!rowHasMatch) return null;

        return {
          ...row,
          eventsByHost: filteredEventsByHost,
        };
      })
      .filter(Boolean) as SynchronizedTimeRow[];
  }, [timeRows, hosts, searchQuery, severityFilter, selectedEventId]);

  // Quick stats
  const totalEventsCount = useMemo(() => {
    return hosts.reduce((acc, h) => acc + h.totalEvents, 0);
  }, [hosts]);

  const totalThreatsCount = useMemo(() => {
    return hosts.reduce((acc, h) => acc + h.threatEventsCount, 0);
  }, [hosts]);

  // CSV Export for Multi-Host Synchronized Audit Log
  const handleExportCsv = () => {
    const headers = ['Timestamp_UTC', 'Relative_Seconds', 'Host_Asset', 'Event_ID', 'Event_Name', 'Severity', 'User', 'IP_Address', 'Process_Image', 'Command_Line', 'Summary'];
    const rows: string[][] = [];

    timeRows.forEach((row) => {
      Object.entries(row.eventsByHost).forEach(([, evList]) => {
        evList.forEach((ev) => {
          rows.push([
            ev.timestamp,
            String(row.relativeSeconds),
            ev.computer,
            String(ev.eventId),
            `"${ev.eventName.replace(/"/g, '""')}"`,
            ev.severity.toUpperCase(),
            ev.user,
            ev.ipAddress || '',
            `"${(ev.processName || '').replace(/"/g, '""')}"`,
            `"${(ev.commandLine || '').replace(/"/g, '""')}"`,
            `"${(ev.summary || '').replace(/"/g, '""')}"`,
          ]);
        });
      });
    });

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `Multi_Host_Forensic_Timeline_${new Date().toISOString().substring(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Jump to first detected critical/anomaly
  const handleJumpToFirstThreat = () => {
    const el = document.querySelector('[data-threat="true"]');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  // Event icon matching ForensicTimelineCard.tsx
  const renderEventIcon = (ev: NormalizedEvtxEvent) => {
    if (ev.isAnomaly || ev.severity === 'critical') {
      return <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />;
    }
    const eid = ev.eventId;
    if ([4624, 4625, 4672, 4720, 4728, 4732, 4756].includes(eid)) {
      return <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />;
    }
    if ([4688, 1, 4104].includes(eid)) {
      return <FileCode className="w-3.5 h-3.5 text-amber-600" />;
    }
    if ([7045, 4697].includes(eid)) {
      return <Cpu className="w-3.5 h-3.5 text-indigo-600" />;
    }
    if ([4698, 4699, 4702].includes(eid)) {
      return <Clock className="w-3.5 h-3.5 text-violet-600" />;
    }
    if ([5140, 5145].includes(eid)) {
      return <Network className="w-3.5 h-3.5 text-teal-600" />;
    }
    if ([1102, 104, 4616, 5001].includes(eid)) {
      return <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />;
    }
    return <Shield className="w-3.5 h-3.5 text-slate-600" />;
  };

  // Node bullet style on the vertical timeline track
  const getBulletStyle = (ev: NormalizedEvtxEvent) => {
    if (ev.isAnomaly || ev.severity === 'critical') {
      return 'border-rose-500 bg-rose-50 text-rose-600';
    }
    if (ev.isThreat || ev.severity === 'high') {
      return 'border-amber-400 bg-amber-50 text-amber-700';
    }
    if (ev.severity === 'medium') {
      return 'border-yellow-400 bg-yellow-50 text-yellow-700';
    }
    const eid = ev.eventId;
    if ([4624, 4625].includes(eid)) return 'border-blue-400 bg-blue-50 text-blue-600';
    if ([4688, 1, 4104].includes(eid)) return 'border-amber-400 bg-amber-50 text-amber-600';
    if ([7045, 4697].includes(eid)) return 'border-indigo-400 bg-indigo-50 text-indigo-600';
    return 'border-slate-300 bg-slate-50 text-slate-600';
  };

  // Event Card styling matching ForensicTimelineCard.tsx
  const getCardStyle = (ev: NormalizedEvtxEvent) => {
    if (ev.isAnomaly || ev.severity === 'critical') {
      return 'bg-rose-50/70 hover:bg-rose-50 border-rose-300 shadow-xs';
    }
    if (ev.isThreat || ev.severity === 'high') {
      return 'bg-amber-50/50 hover:bg-amber-50/80 border-amber-300 shadow-xs';
    }
    if (ev.severity === 'medium') {
      return 'bg-yellow-50/40 hover:bg-yellow-50/70 border-yellow-300 shadow-xs';
    }
    const eid = ev.eventId;
    if ([4624, 4625].includes(eid)) return 'bg-blue-50/30 hover:bg-blue-50/60 border-blue-200/80 shadow-2xs';
    if ([4688, 1, 4104].includes(eid)) return 'bg-amber-50/30 hover:bg-amber-50/60 border-amber-200/80 shadow-2xs';
    if ([7045, 4697].includes(eid)) return 'bg-indigo-50/30 hover:bg-indigo-50/60 border-indigo-200/80 shadow-2xs';
    return 'bg-white hover:bg-slate-50 border-slate-200 shadow-2xs';
  };

  // Copy event details as JSON
  const handleCopyJson = (ev: NormalizedEvtxEvent) => {
    navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    setCopiedState(true);
    setTimeout(() => setCopiedState(false), 2000);
  };

  return (
    <div className="space-y-5">
      {/* 1. Header & Controls Panel (Light Theme matching ForensicTimelineCard) */}
      <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-5 border-b border-slate-100">
          <div>
            <div className="flex items-center gap-2.5 mb-1 flex-wrap">
              <span className="p-1.5 bg-indigo-50 text-indigo-600 rounded-lg">
                <Clock className="w-5 h-5" />
              </span>
              <h3 className="text-base font-bold text-slate-900">
                Synchronized Multi-EVTX Forensic Event Timeline
              </h3>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
                {hosts.length} Windows Event Logs
              </span>
              {lateralChains.length > 0 && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200 flex items-center gap-1">
                  <Zap className="w-3 h-3 text-amber-600" />
                  <span>{lateralChains.length} Lateral Movement Chain(s)</span>
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 font-mono">
              Side-by-side vertical event lanes with strict timestamp synchronization across independent host event logs.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            {onSwitchToTable && (
              <button
                onClick={onSwitchToTable}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 shadow-2xs transition-colors cursor-pointer"
              >
                <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
                <span>Switch to Table View</span>
              </button>
            )}

            {totalThreatsCount > 0 && (
              <button
                onClick={handleJumpToFirstThreat}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 shadow-2xs transition-colors cursor-pointer"
              >
                <Flame className="w-3.5 h-3.5 text-rose-500" />
                <span>Jump to First Threat</span>
              </button>
            )}

            <button
              onClick={handleExportCsv}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 shadow-2xs transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-slate-500" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Search, Filter Chips, and Density Toolbar */}
        <div className="pt-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
            {/* Search Input */}
            <div className="relative min-w-[220px] max-w-sm">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search across all hosts (users, processes, CLI, event IDs)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-slate-400 hover:text-slate-600 font-mono"
                >
                  clear
                </button>
              )}
            </div>

            {/* Severity Quick Chips */}
            <div className="flex items-center bg-slate-100 p-0.5 rounded-xl border border-slate-200">
              <button
                type="button"
                onClick={() => setSeverityFilter('all')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  severityFilter === 'all'
                    ? 'bg-white text-slate-900 shadow-2xs font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                All Events ({totalEventsCount})
              </button>
              <button
                type="button"
                onClick={() => setSeverityFilter('threats')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg transition-all flex items-center gap-1 cursor-pointer ${
                  severityFilter === 'threats'
                    ? 'bg-white text-rose-700 shadow-2xs font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <AlertTriangle className="w-3 h-3 text-rose-500" />
                <span>Threats &amp; Anomalies ({totalThreatsCount})</span>
              </button>
              <button
                type="button"
                onClick={() => setSeverityFilter('critical')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  severityFilter === 'critical'
                    ? 'bg-white text-rose-900 shadow-2xs font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Critical Only
              </button>
            </div>

            {/* Event ID Dropdown */}
            {uniqueEventIds.length > 1 && (
              <select
                value={selectedEventId}
                onChange={(e) => setSelectedEventId(e.target.value)}
                className="bg-slate-50 border border-slate-200 rounded-xl px-2.5 py-1.5 text-xs text-slate-700 font-mono focus:outline-none cursor-pointer"
              >
                <option value="all">All Event IDs ({uniqueEventIds.length})</option>
                {uniqueEventIds.map((eid) => (
                  <option key={eid} value={String(eid)}>
                    Event {eid} — {getEventName(eid)}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Density Toggle and Count */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-xl border border-slate-200">
              <button
                type="button"
                onClick={() => setDensityMode('comfortable')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  densityMode === 'comfortable'
                    ? 'bg-white text-slate-900 shadow-2xs font-bold'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                Detailed
              </button>
              <button
                type="button"
                onClick={() => setDensityMode('compact')}
                className={`px-2.5 py-1 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  densityMode === 'compact'
                    ? 'bg-white text-slate-900 shadow-2xs font-bold'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                Compact
              </button>
            </div>

            <div className="text-xs font-mono text-slate-500">
              Showing {filteredTimeRows.length} synchronized moments
            </div>
          </div>
        </div>
      </div>

      {/* 2. Side-by-Side Synchronized Vertical Swimlane Canvas (Light Theme) */}
      <div
        ref={timelineContainerRef}
        data-testid="swimlane-scroll-container"
        className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-x-auto relative min-h-[600px] max-h-[750px] overflow-y-auto"
      >
        {/* Sticky Swimlane Column Headers */}
        <div className="sticky top-0 z-20 bg-slate-50/95 backdrop-blur-xs border-b border-slate-200 shadow-xs">
          <div
            className="grid divide-x divide-slate-200"
            style={{
              gridTemplateColumns: `130px repeat(${hosts.length}, minmax(360px, 1fr))`,
            }}
          >
            {/* Time Spine Column Header */}
            <div className="p-3 bg-slate-100/70 flex flex-col justify-center items-center text-center">
              <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-slate-700">
                <Clock className="w-3.5 h-3.5 text-indigo-600" />
                <span>TIME AXIS</span>
              </div>
              <span className="text-[10px] font-mono text-slate-500 mt-0.5">Chronological UTC</span>
            </div>

            {/* One Header per Host Swimlane */}
            {hosts.map((host, hIdx) => (
              <div
                key={host.jobId}
                className="p-3 bg-slate-50 flex items-center justify-between gap-3 relative"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shrink-0 shadow-2xs">
                    <Server className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-bold text-slate-900 truncate font-mono">
                        {host.computer}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-200/80 text-slate-700 font-semibold">
                        Host #{hIdx + 1}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono truncate flex items-center gap-1.5 mt-0.5">
                      <span className="truncate">{host.filename}</span>
                      <span>•</span>
                      <span className="text-slate-700 font-semibold">{host.totalEvents} events</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {host.threatEventsCount > 0 && (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1">
                      <Flame className="w-2.5 h-2.5 text-rose-500" />
                      <span>{host.threatEventsCount} Threats</span>
                    </span>
                  )}
                  <button
                    onClick={() => onSelectJob(host.jobId)}
                    title={`Open detailed tab for ${host.filename}`}
                    className="p-1.5 rounded-lg bg-white border border-slate-200 text-slate-500 hover:text-indigo-600 hover:border-indigo-300 transition-colors cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Swimlane Rows Body */}
        <div className="divide-y divide-slate-100">
          {filteredTimeRows.length === 0 ? (
            <div className="py-20 text-center space-y-2 bg-slate-50/50">
              <CheckCircle2 className="w-8 h-8 text-slate-400 mx-auto" />
              <div className="text-sm font-semibold text-slate-700 font-mono">No events match the active filters.</div>
              <p className="text-xs text-slate-500">Try adjusting the severity filter, event ID, or clearing the search text.</p>
            </div>
          ) : (
            filteredTimeRows.map((row) => {
              const isHovered = hoveredEpoch === row.epoch;

              return (
                <div key={row.epoch} className="relative">
                  {/* Cross-Host Lateral Connection Callout Banner (Light Theme) */}
                  {row.isCrossHostInteraction && (
                    <div className="bg-indigo-50/90 border-y border-indigo-200 px-4 py-1.5 flex items-center justify-between text-xs font-mono text-indigo-900 shadow-2xs">
                      <div className="flex items-center gap-2">
                        <Zap className="w-3.5 h-3.5 text-indigo-600 animate-bounce" />
                        <span className="font-bold tracking-wide uppercase text-[11px] text-indigo-950">
                          Cross-Host Lateral Movement / Synchronized Pivot
                        </span>
                        <span className="text-indigo-400">•</span>
                        <span className="text-indigo-700 font-semibold">{row.crossHostNotes}</span>
                      </div>
                      <span className="text-[10px] text-indigo-600 font-semibold">T+{row.relativeSeconds}s</span>
                    </div>
                  )}

                  {/* Synchronized Row Grid: Time Spine + Host Columns */}
                  <div
                    onMouseEnter={() => setHoveredEpoch(row.epoch)}
                    onMouseLeave={() => setHoveredEpoch(null)}
                    className={`grid divide-x divide-slate-200 transition-colors ${
                      isHovered ? 'bg-indigo-50/20' : 'bg-white'
                    }`}
                    style={{
                      gridTemplateColumns: `130px repeat(${hosts.length}, minmax(360px, 1fr))`,
                    }}
                  >
                    {/* Time Spine Cell */}
                    <div className="p-3 bg-slate-50/40 flex flex-col justify-center items-center text-center relative select-none">
                      <div className="w-2.5 h-2.5 rounded-full bg-indigo-500 border-2 border-white ring-2 ring-indigo-200 mb-1" />
                      <span className="text-xs font-mono font-bold text-slate-800 tracking-tight">
                        {row.timeLabel.replace(' UTC', '')}
                      </span>
                      <span className="text-[10px] font-mono text-indigo-600 font-semibold mt-0.5">
                        {row.relativeSeconds === 0 ? 'T+0s (Start)' : `+${row.relativeSeconds}s`}
                      </span>
                      <span className="text-[9px] font-mono text-slate-400 mt-0.5">{row.dateLabel}</span>
                    </div>

                    {/* Host Columns for this Time Row */}
                    {hosts.map((host) => {
                      const hostEvents = row.eventsByHost[host.jobId] || [];

                      return (
                        <div key={host.jobId} className="p-3 relative flex flex-col justify-center min-h-[90px]">
                          {hostEvents.length === 0 ? (
                            /* Idle track guideline when no events occurred on this host at this second */
                            <div className="border-l-2 border-dashed border-slate-200 ml-4 h-full min-h-[70px]" />
                          ) : (
                            /* Event Card(s) along vertical timeline line */
                            <div className="border-l-2 border-slate-200 ml-4 space-y-3 py-1">
                              {hostEvents.map((ev) => {
                                const isThreat = ev.isThreat || ['critical', 'high'].includes(ev.severity);

                                return (
                                  <div key={ev.id} className="relative pl-6 group">
                                    {/* Node Bullet with Custom Icon */}
                                    <div
                                      className={`absolute -left-[15px] top-2 w-7 h-7 rounded-full border-2 flex items-center justify-center shadow-2xs transition-transform group-hover:scale-110 z-5 ${getBulletStyle(
                                        ev
                                      )}`}
                                      title={`Event ${ev.eventId} (${ev.category})`}
                                    >
                                      {renderEventIcon(ev)}
                                    </div>

                                    {/* Event Card matching ForensicTimelineCard light style */}
                                    <div
                                      data-testid="swimlane-event-card"
                                      data-threat={isThreat ? 'true' : 'false'}
                                      onClick={() => setSelectedEventForModal(ev)}
                                      className={`rounded-2xl border p-3.5 cursor-pointer transition-all duration-150 hover:shadow-md ${getCardStyle(
                                        ev
                                      )}`}
                                    >
                                      {/* Header Row inside card */}
                                      <div className="flex items-center justify-between gap-2 mb-1.5 flex-wrap">
                                        <div className="flex items-center gap-1.5 flex-wrap">
                                          {/* Event ID Pill */}
                                          {ev.eventId > 0 ? (
                                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200 shadow-2xs">
                                              Event {ev.eventId}
                                            </span>
                                          ) : (
                                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-100 text-slate-700 border border-slate-200 shadow-2xs">
                                              {ev.category || 'Security'}
                                            </span>
                                          )}

                                          {/* Severity Tag */}
                                          <span
                                            className={`px-1.5 py-0.2 rounded text-[9px] font-mono uppercase font-semibold border ${
                                              ev.severity === 'critical'
                                                ? 'bg-rose-100 text-rose-800 border-rose-300'
                                                : ev.severity === 'high'
                                                ? 'bg-amber-100 text-amber-800 border-amber-300'
                                                : ev.severity === 'medium'
                                                ? 'bg-yellow-100 text-yellow-800 border-yellow-300'
                                                : 'bg-slate-100 text-slate-600 border-slate-200'
                                            }`}
                                          >
                                            {ev.severity}
                                          </span>

                                          {/* Anomaly Badge */}
                                          {ev.isAnomaly && (
                                            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">
                                              ANOMALY
                                            </span>
                                          )}
                                        </div>

                                        {/* Logon Type Pill */}
                                        {ev.logonType && (
                                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 border border-slate-200">
                                            LogonType {ev.logonType}
                                          </span>
                                        )}
                                      </div>

                                      {/* Title / Action */}
                                      <div className="mb-1">
                                        <h4 className="text-xs font-bold text-slate-900 tracking-tight leading-snug">
                                          {ev.eventName}
                                        </h4>
                                      </div>

                                      {/* Detailed view info */}
                                      {densityMode === 'comfortable' && (
                                        <div className="space-y-1.5 mt-1 text-[11px] font-mono text-slate-600">
                                          {/* Description / Summary */}
                                          {ev.description && (
                                            <p className="line-clamp-2 leading-relaxed text-slate-600">
                                              {ev.description}
                                            </p>
                                          )}

                                          {/* User & IP */}
                                          <div className="flex items-center gap-3 text-slate-500 flex-wrap pt-0.5">
                                            {ev.user && ev.user !== '-' && (
                                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 text-[10px]">
                                                <User className="w-3 h-3 text-amber-600" />
                                                <span className="font-semibold">{ev.user}</span>
                                              </span>
                                            )}

                                            {ev.ipAddress && (
                                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px]">
                                                <Globe className="w-3 h-3 text-slate-500" />
                                                <span>{ev.ipAddress}</span>
                                              </span>
                                            )}
                                          </div>

                                          {/* Command line preview box */}
                                          {ev.commandLine && (
                                            <div className="mt-1 p-1.5 rounded-lg bg-slate-100/90 border border-slate-200 text-[10px] font-mono text-slate-800 truncate flex items-center gap-1.5">
                                              <Terminal className="w-3 h-3 text-slate-500 shrink-0" />
                                              <span className="truncate">
                                                <ReferencedText
                                                  text={ev.commandLine}
                                                  workspaceJobs={jobs}
                                                  onSelectJob={onSelectJob}
                                                />
                                              </span>
                                            </div>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* 3. Event Detail Inspector Modal (Light Theme) */}
      {selectedEventForModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-2xl w-full max-h-[85vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/80">
              <div className="flex items-center gap-2.5">
                <div
                  className={`w-9 h-9 rounded-xl border flex items-center justify-center shadow-2xs ${getBulletStyle(
                    selectedEventForModal
                  )}`}
                >
                  {renderEventIcon(selectedEventForModal)}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-900 font-mono">
                      Event {selectedEventForModal.eventId}
                    </span>
                    <span
                      className={`px-2 py-0.2 rounded text-[10px] font-mono uppercase font-semibold border ${
                        selectedEventForModal.severity === 'critical'
                          ? 'bg-rose-100 text-rose-800 border-rose-300'
                          : selectedEventForModal.severity === 'high'
                          ? 'bg-amber-100 text-amber-800 border-amber-300'
                          : 'bg-slate-100 text-slate-600 border-slate-200'
                      }`}
                    >
                      {selectedEventForModal.severity}
                    </span>
                    {selectedEventForModal.isAnomaly && (
                      <span className="px-2 py-0.2 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300">
                        ANOMALY
                      </span>
                    )}
                  </div>
                  <h3 className="text-sm font-bold text-slate-900 mt-0.5">
                    {selectedEventForModal.eventName}
                  </h3>
                </div>
              </div>

              <button
                onClick={() => setSelectedEventForModal(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs font-mono text-slate-700">
              {/* Host & Timestamp Card */}
              <div className="grid grid-cols-2 gap-3 bg-slate-50 p-3.5 rounded-2xl border border-slate-200">
                <div>
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-0.5">
                    Target Host / Computer
                  </span>
                  <span className="text-xs font-bold text-slate-900">
                    {selectedEventForModal.computer}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-0.5">
                    Timestamp (UTC)
                  </span>
                  <span className="text-xs font-bold text-slate-900">
                    {selectedEventForModal.timestamp}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-0.5">
                    Log Source File
                  </span>
                  <button
                    onClick={() => {
                      const jId = selectedEventForModal.jobId;
                      setSelectedEventForModal(null);
                      if (onSelectJob && jId) onSelectJob(jId);
                    }}
                    className="text-xs font-bold text-indigo-700 hover:text-indigo-900 truncate flex items-center gap-1 hover:underline cursor-pointer"
                    title={`Click to open ${selectedEventForModal.filename}`}
                  >
                    <span className="truncate">{selectedEventForModal.filename}</span>
                    <ExternalLink className="w-3 h-3 text-indigo-500 shrink-0" />
                  </button>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-0.5">
                    Category
                  </span>
                  <span className="text-xs text-slate-800">
                    {selectedEventForModal.category}
                  </span>
                </div>
              </div>

              {/* Linked Artifact in Incident Badge */}
              {(() => {
                const linkedJob = (() => {
                  if (!jobs || jobs.length === 0) return null;
                  return findReferencedJob(selectedEventForModal.commandLine || '', jobs, selectedEventForModal.jobId) ||
                    findReferencedJob(selectedEventForModal.description || '', jobs, selectedEventForModal.jobId) ||
                    (selectedEventForModal.processName ? findReferencedJob(selectedEventForModal.processName, jobs, selectedEventForModal.jobId) : null);
                })();

                if (!linkedJob) return null;

                return (
                  <div className="p-3.5 bg-indigo-50 border border-indigo-200 rounded-2xl flex items-center justify-between gap-3 shadow-xs">
                    <div className="flex items-center gap-2">
                      <Zap className="w-4 h-4 text-indigo-600 shrink-0" />
                      <span className="text-xs font-bold text-indigo-950">
                        Referenced Incident Artifact:
                      </span>
                      <span className="font-mono text-xs font-bold text-indigo-800">
                        {linkedJob.filename}
                      </span>
                    </div>
                    <button
                      onClick={() => {
                        const targetId = linkedJob.jobId;
                        setSelectedEventForModal(null);
                        if (onSelectJob && targetId) onSelectJob(targetId);
                      }}
                      className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold text-xs rounded-xl flex items-center gap-1.5 cursor-pointer shadow-xs transition-colors shrink-0"
                    >
                      <span>Jump to Artifact</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })()}

              {/* Event Summary */}
              {selectedEventForModal.description && (
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block">
                    Narrative Summary
                  </span>
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl leading-relaxed text-slate-700">
                    <ReferencedText
                      text={selectedEventForModal.description}
                      workspaceJobs={jobs}
                      onSelectJob={onSelectJob}
                    />
                  </div>
                </div>
              )}

              {/* User, IP, and Process Metadata */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-1">
                    Subject / Target User
                  </span>
                  <span className="text-xs font-bold text-amber-800">
                    {selectedEventForModal.user}
                  </span>
                </div>

                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block mb-1">
                    Source IP Address
                  </span>
                  <span className="text-xs font-bold text-slate-900">
                    {selectedEventForModal.ipAddress || 'Local / N/A'}
                  </span>
                </div>
              </div>

              {/* Command Line / Process */}
              {selectedEventForModal.commandLine && (
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block">
                    Executed Command Line
                  </span>
                  <div className="p-3 bg-slate-900 text-slate-100 rounded-xl text-xs font-mono break-all selection:bg-indigo-500 selection:text-white">
                    <ReferencedText
                      text={selectedEventForModal.commandLine}
                      workspaceJobs={jobs}
                      onSelectJob={onSelectJob}
                    />
                  </div>
                </div>
              )}

              {/* Raw Details / JSON */}
              {Object.keys(selectedEventForModal.details || {}).length > 0 && (
                <div className="space-y-1">
                  <span className="text-[10px] text-slate-400 font-semibold uppercase block">
                    Extended Event Parameters
                  </span>
                  <pre className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-[11px] font-mono text-slate-800 overflow-x-auto max-h-40">
                    {JSON.stringify(selectedEventForModal.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-100 bg-slate-50/80 flex items-center justify-between">
              <button
                onClick={() => handleCopyJson(selectedEventForModal)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                {copiedState ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    <span className="text-emerald-700">Copied to Clipboard!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-500" />
                    <span>Copy Event JSON</span>
                  </>
                )}
              </button>

              <button
                onClick={() => setSelectedEventForModal(null)}
                className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors cursor-pointer shadow-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
