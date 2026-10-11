import React, { useState, useEffect, useMemo } from 'react';
import {
  Clock,
  Download,
  AlertTriangle,
  Archive,
  Camera,
  RefreshCw,
  CheckCircle2,
  Calendar,
  History,
  UploadCloud,
  FilePlus,
  FileEdit,
  HardDrive,
  Save,
  Zap,
  FileSpreadsheet,
  FileCode,
  Send,
  Network,
  Paperclip,
  Globe,
  CalendarX,
  ShieldCheck,
  Lock,
  Cpu,
  Search,
  Crosshair,
  Bug,
  Flame,
  Radio,
  SlidersHorizontal,
  CheckSquare,
  Square,
  Sparkles,
  Activity,
  X,
  RotateCcw,
  FileText,
  Layers,
  ChevronDown
} from 'lucide-react';
import { ForensicTimelineData } from '../types';
import { MultiArtifactSwimlaneCanvas } from './MultiArtifactSwimlaneCanvas';

interface ForensicTimelineCardProps {
  jobId: string;
}

interface EventTypeStyle {
  label: string;
  icon: (className?: string) => React.ReactNode;
  iconColor: string;
  bulletBg: string;
  bulletBorder: string;
  badgeBg: string;
  badgeText: string;
  badgeBorder: string;
  cardBg: string;
  cardBorder: string;
}

const EVENT_TYPE_CONFIG: Record<string, EventTypeStyle> = {
  FILE_INGESTED: {
    label: 'File Ingested',
    icon: (c) => <UploadCloud className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-700',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-slate-50/60 hover:bg-slate-50',
    cardBorder: 'border-slate-200/80',
  },
  PREVIOUS_SUBMISSION: {
    label: 'Previous Submission',
    icon: (c) => <History className={c} />,
    iconColor: 'text-emerald-600',
    bulletBg: 'bg-emerald-50',
    bulletBorder: 'border-emerald-500',
    badgeBg: 'bg-emerald-50',
    badgeText: 'text-emerald-700',
    badgeBorder: 'border-emerald-200',
    cardBg: 'bg-emerald-50/30 hover:bg-emerald-50/70',
    cardBorder: 'border-emerald-200',
  },
  DOCUMENT_CREATED: {
    label: 'Document Created',
    icon: (c) => <FilePlus className={c} />,
    iconColor: 'text-indigo-600',
    bulletBg: 'bg-indigo-50',
    bulletBorder: 'border-indigo-400',
    badgeBg: 'bg-indigo-50',
    badgeText: 'text-indigo-700',
    badgeBorder: 'border-indigo-200',
    cardBg: 'bg-indigo-50/20 hover:bg-indigo-50/50',
    cardBorder: 'border-indigo-200/80',
  },
  DOCUMENT_MODIFIED: {
    label: 'Document Modified',
    icon: (c) => <FileEdit className={c} />,
    iconColor: 'text-violet-600',
    bulletBg: 'bg-violet-50',
    bulletBorder: 'border-violet-400',
    badgeBg: 'bg-violet-50',
    badgeText: 'text-violet-700',
    badgeBorder: 'border-violet-200',
    cardBg: 'bg-violet-50/20 hover:bg-violet-50/50',
    cardBorder: 'border-violet-200/80',
  },
  PHOTO_CAPTURED: {
    label: 'EXIF Sensor Capture',
    icon: (c) => <Camera className={c} />,
    iconColor: 'text-purple-600',
    bulletBg: 'bg-purple-50',
    bulletBorder: 'border-purple-400',
    badgeBg: 'bg-purple-50',
    badgeText: 'text-purple-700',
    badgeBorder: 'border-purple-200',
    cardBg: 'bg-purple-50/20 hover:bg-purple-50/50',
    cardBorder: 'border-purple-200/80',
  },
  FILE_CREATED: {
    label: 'Filesystem Created',
    icon: (c) => <HardDrive className={c} />,
    iconColor: 'text-sky-600',
    bulletBg: 'bg-sky-50',
    bulletBorder: 'border-sky-400',
    badgeBg: 'bg-sky-50',
    badgeText: 'text-sky-700',
    badgeBorder: 'border-sky-200',
    cardBg: 'bg-sky-50/20 hover:bg-sky-50/50',
    cardBorder: 'border-sky-200/80',
  },
  FILE_MODIFIED: {
    label: 'Filesystem Modified',
    icon: (c) => <Save className={c} />,
    iconColor: 'text-cyan-600',
    bulletBg: 'bg-cyan-50',
    bulletBorder: 'border-cyan-400',
    badgeBg: 'bg-cyan-50',
    badgeText: 'text-cyan-700',
    badgeBorder: 'border-cyan-200',
    cardBg: 'bg-cyan-50/20 hover:bg-cyan-50/50',
    cardBorder: 'border-cyan-200/80',
  },
  TIMESTOMPING_INVERTED_DATES: {
    label: 'Timestomping: Inverted Dates',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-50',
    bulletBorder: 'border-rose-500',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-800',
    badgeBorder: 'border-rose-300',
    cardBg: 'bg-rose-50/80',
    cardBorder: 'border-rose-300',
  },
  TIMESTOMPING_FUTURE_TIMESTAMP: {
    label: 'Timestomping: Future Date',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-50',
    bulletBorder: 'border-rose-500',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-800',
    badgeBorder: 'border-rose-300',
    cardBg: 'bg-rose-50/80',
    cardBorder: 'border-rose-300',
  },
  TIMESTOMPING_FINDING: {
    label: 'Timestomping Finding',
    icon: (c) => <Zap className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-50',
    bulletBorder: 'border-rose-500',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-800',
    badgeBorder: 'border-rose-300',
    cardBg: 'bg-rose-50/80',
    cardBorder: 'border-rose-300',
  },
  OFFICE_DOCUMENT_CREATED: {
    label: 'Office Document Created',
    icon: (c) => <FileSpreadsheet className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-700',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  OFFICE_DOCUMENT_MODIFIED: {
    label: 'Office Document Modified',
    icon: (c) => <FileSpreadsheet className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-700',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  PDF_DOCUMENT_CREATED: {
    label: 'PDF Document Created',
    icon: (c) => <FileCode className={c} />,
    iconColor: 'text-red-600',
    bulletBg: 'bg-red-50',
    bulletBorder: 'border-red-400',
    badgeBg: 'bg-red-50',
    badgeText: 'text-red-700',
    badgeBorder: 'border-red-200',
    cardBg: 'bg-red-50/20 hover:bg-red-50/50',
    cardBorder: 'border-red-200/80',
  },
  PDF_DOCUMENT_MODIFIED: {
    label: 'PDF Document Modified',
    icon: (c) => <FileCode className={c} />,
    iconColor: 'text-red-600',
    bulletBg: 'bg-red-50',
    bulletBorder: 'border-red-400',
    badgeBg: 'bg-red-50',
    badgeText: 'text-red-700',
    badgeBorder: 'border-red-200',
    cardBg: 'bg-red-50/20 hover:bg-red-50/50',
    cardBorder: 'border-red-200/80',
  },
  EMAIL_ORIGIN_DISPATCH: {
    label: 'Email Sent Date',
    icon: (c) => <Send className={c} />,
    iconColor: 'text-cyan-600',
    bulletBg: 'bg-cyan-50',
    bulletBorder: 'border-cyan-400',
    badgeBg: 'bg-cyan-50',
    badgeText: 'text-cyan-700',
    badgeBorder: 'border-cyan-200',
    cardBg: 'bg-cyan-50/20 hover:bg-cyan-50/50',
    cardBorder: 'border-cyan-200/80',
  },
  EMAIL_TRANSIT_RELAY: {
    label: 'Email Relay Hop',
    icon: (c) => <Network className={c} />,
    iconColor: 'text-teal-600',
    bulletBg: 'bg-teal-50',
    bulletBorder: 'border-teal-400',
    badgeBg: 'bg-teal-50',
    badgeText: 'text-teal-700',
    badgeBorder: 'border-teal-200',
    cardBg: 'bg-teal-50/20 hover:bg-teal-50/50',
    cardBorder: 'border-teal-200/80',
  },
  EMBEDDED_FILE_CREATED: {
    label: 'Embedded File Created',
    icon: (c) => <FilePlus className={c} />,
    iconColor: 'text-indigo-600',
    bulletBg: 'bg-indigo-50',
    bulletBorder: 'border-indigo-400',
    badgeBg: 'bg-indigo-50',
    badgeText: 'text-indigo-700',
    badgeBorder: 'border-indigo-200',
    cardBg: 'bg-indigo-50/20 hover:bg-indigo-50/50',
    cardBorder: 'border-indigo-200/80',
  },
  EMBEDDED_FILE_MODIFIED: {
    label: 'Embedded File Modified',
    icon: (c) => <FileEdit className={c} />,
    iconColor: 'text-violet-600',
    bulletBg: 'bg-violet-50',
    bulletBorder: 'border-violet-400',
    badgeBg: 'bg-violet-50',
    badgeText: 'text-violet-700',
    badgeBorder: 'border-violet-200',
    cardBg: 'bg-violet-50/20 hover:bg-violet-50/50',
    cardBorder: 'border-violet-200/80',
  },
  ARCHIVE_MEMBER_CREATED: {
    label: 'Archive Member Created',
    icon: (c) => <Archive className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-50',
    bulletBorder: 'border-amber-400',
    badgeBg: 'bg-amber-50',
    badgeText: 'text-amber-800',
    badgeBorder: 'border-amber-200',
    cardBg: 'bg-amber-50/20 hover:bg-amber-50/50',
    cardBorder: 'border-amber-200/80',
  },
  ARCHIVE_MEMBER_MODIFIED: {
    label: 'Archive Member Modified',
    icon: (c) => <Archive className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-50',
    bulletBorder: 'border-amber-400',
    badgeBg: 'bg-amber-50',
    badgeText: 'text-amber-800',
    badgeBorder: 'border-amber-200',
    cardBg: 'bg-amber-50/20 hover:bg-amber-50/50',
    cardBorder: 'border-amber-200/80',
  },
  ATTACHMENT_TIMESTAMP: {
    label: 'Email Attachment',
    icon: (c) => <Paperclip className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-50',
    bulletBorder: 'border-amber-400',
    badgeBg: 'bg-amber-50',
    badgeText: 'text-amber-800',
    badgeBorder: 'border-amber-200',
    cardBg: 'bg-amber-50/20 hover:bg-amber-50/50',
    cardBorder: 'border-amber-200/80',
  },
  ATTACHMENT_PAYLOAD_AUTHORED: {
    label: 'Archive Member Authored',
    icon: (c) => <Archive className={c} />,
    iconColor: 'text-orange-600',
    bulletBg: 'bg-orange-50',
    bulletBorder: 'border-orange-400',
    badgeBg: 'bg-orange-50',
    badgeText: 'text-orange-800',
    badgeBorder: 'border-orange-200',
    cardBg: 'bg-orange-50/20 hover:bg-orange-50/50',
    cardBorder: 'border-orange-200/80',
  },
  EMAIL_SENDER_DOMAIN_REGISTERED: {
    label: 'Sender Domain Registered',
    icon: (c) => <Globe className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-700',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  URL_DOMAIN_REGISTERED: {
    label: 'URL Domain Registered',
    icon: (c) => <Globe className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-700',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  URL_DOMAIN_UPDATED: {
    label: 'URL Domain Renewed',
    icon: (c) => <RefreshCw className={c} />,
    iconColor: 'text-sky-600',
    bulletBg: 'bg-sky-50',
    bulletBorder: 'border-sky-400',
    badgeBg: 'bg-sky-50',
    badgeText: 'text-sky-700',
    badgeBorder: 'border-sky-200',
    cardBg: 'bg-sky-50/20 hover:bg-sky-50/50',
    cardBorder: 'border-sky-200/80',
  },
  DOMAIN_REGISTERED: {
    label: 'Target Domain Registered',
    icon: (c) => <Globe className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-700',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  DOMAIN_UPDATED: {
    label: 'Target Domain Renewed',
    icon: (c) => <RefreshCw className={c} />,
    iconColor: 'text-sky-600',
    bulletBg: 'bg-sky-50',
    bulletBorder: 'border-sky-400',
    badgeBg: 'bg-sky-50',
    badgeText: 'text-sky-700',
    badgeBorder: 'border-sky-200',
    cardBg: 'bg-sky-50/20 hover:bg-sky-50/50',
    cardBorder: 'border-sky-200/80',
  },
  DOMAIN_EXPIRATION: {
    label: 'Domain Expiration',
    icon: (c) => <CalendarX className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-50',
    bulletBorder: 'border-amber-400',
    badgeBg: 'bg-amber-50',
    badgeText: 'text-amber-800',
    badgeBorder: 'border-amber-200',
    cardBg: 'bg-amber-50/20 hover:bg-amber-50/50',
    cardBorder: 'border-amber-200/80',
  },
  CERTIFICATE_ISSUED: {
    label: 'TLS Certificate Issued',
    icon: (c) => <ShieldCheck className={c} />,
    iconColor: 'text-emerald-600',
    bulletBg: 'bg-emerald-50',
    bulletBorder: 'border-emerald-400',
    badgeBg: 'bg-emerald-50',
    badgeText: 'text-emerald-700',
    badgeBorder: 'border-emerald-200',
    cardBg: 'bg-emerald-50/20 hover:bg-emerald-50/50',
    cardBorder: 'border-emerald-200/80',
  },
  CERTIFICATE_EXPIRATION: {
    label: 'TLS Certificate Expiry',
    icon: (c) => <Lock className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-50',
    bulletBorder: 'border-amber-400',
    badgeBg: 'bg-amber-50',
    badgeText: 'text-amber-800',
    badgeBorder: 'border-amber-200',
    cardBg: 'bg-amber-50/20 hover:bg-amber-50/50',
    cardBorder: 'border-amber-200/80',
  },
  PE_COMPILATION_TIMESTAMP: {
    label: 'PE Binary Compiled',
    icon: (c) => <Cpu className={c} />,
    iconColor: 'text-purple-600',
    bulletBg: 'bg-purple-50',
    bulletBorder: 'border-purple-400',
    badgeBg: 'bg-purple-50',
    badgeText: 'text-purple-700',
    badgeBorder: 'border-purple-200',
    cardBg: 'bg-purple-50/20 hover:bg-purple-50/50',
    cardBorder: 'border-purple-200/80',
  },
  VT_FIRST_SEEN: {
    label: 'VirusTotal First Seen',
    icon: (c) => <Search className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-50',
    bulletBorder: 'border-rose-400',
    badgeBg: 'bg-rose-50',
    badgeText: 'text-rose-700',
    badgeBorder: 'border-rose-200',
    cardBg: 'bg-rose-50/20 hover:bg-rose-50/50',
    cardBorder: 'border-rose-200/80',
  },
  VT_LAST_ANALYSIS: {
    label: 'VirusTotal Last Scan',
    icon: (c) => <CheckCircle2 className={c} />,
    iconColor: 'text-indigo-600',
    bulletBg: 'bg-indigo-50',
    bulletBorder: 'border-indigo-400',
    badgeBg: 'bg-indigo-50',
    badgeText: 'text-indigo-700',
    badgeBorder: 'border-indigo-200',
    cardBg: 'bg-indigo-50/20 hover:bg-indigo-50/50',
    cardBorder: 'border-indigo-200/80',
  },
  CROWDSTRIKE_HYBRID_ANALYSIS: {
    label: 'CrowdStrike Falcon Sandbox',
    icon: (c) => <Crosshair className={c} />,
    iconColor: 'text-purple-600',
    bulletBg: 'bg-purple-50',
    bulletBorder: 'border-purple-500',
    badgeBg: 'bg-purple-50',
    badgeText: 'text-purple-700',
    badgeBorder: 'border-purple-200',
    cardBg: 'bg-purple-50/20 hover:bg-purple-50/50',
    cardBorder: 'border-purple-200/80',
  },
  MALWAREBAZAAR_FIRST_SEEN: {
    label: 'MalwareBazaar Ingest',
    icon: (c) => <Bug className={c} />,
    iconColor: 'text-red-600',
    bulletBg: 'bg-red-50',
    bulletBorder: 'border-red-500',
    badgeBg: 'bg-red-50',
    badgeText: 'text-red-700',
    badgeBorder: 'border-red-200',
    cardBg: 'bg-red-50/20 hover:bg-red-50/50',
    cardBorder: 'border-red-200/80',
  },
  THREATFOX_FIRST_SEEN: {
    label: 'ThreatFox Threat IOC',
    icon: (c) => <Flame className={c} />,
    iconColor: 'text-orange-600',
    bulletBg: 'bg-orange-50',
    bulletBorder: 'border-orange-500',
    badgeBg: 'bg-orange-50',
    badgeText: 'text-orange-800',
    badgeBorder: 'border-orange-200',
    cardBg: 'bg-orange-50/20 hover:bg-orange-50/50',
    cardBorder: 'border-orange-200/80',
  },
  OTX_PULSE_REPORTED: {
    label: 'AlienVault OTX Pulse',
    icon: (c) => <Radio className={c} />,
    iconColor: 'text-violet-600',
    bulletBg: 'bg-violet-50',
    bulletBorder: 'border-violet-400',
    badgeBg: 'bg-violet-50',
    badgeText: 'text-violet-700',
    badgeBorder: 'border-violet-200',
    cardBg: 'bg-violet-50/20 hover:bg-violet-50/50',
    cardBorder: 'border-violet-200/80',
  },
  EVTX_PROCESS_CREATION: {
    label: 'EVTX Process Created',
    icon: (c) => <FileCode className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-50',
    bulletBorder: 'border-amber-400',
    badgeBg: 'bg-amber-50',
    badgeText: 'text-amber-800',
    badgeBorder: 'border-amber-200',
    cardBg: 'bg-amber-50/20 hover:bg-amber-50/50',
    cardBorder: 'border-amber-200/80',
  },
  EVTX_USER_LOGON: {
    label: 'EVTX User Logon',
    icon: (c) => <ShieldCheck className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-800',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  EVTX_SERVICE_INSTALLED: {
    label: 'EVTX Service Installed',
    icon: (c) => <Cpu className={c} />,
    iconColor: 'text-indigo-600',
    bulletBg: 'bg-indigo-50',
    bulletBorder: 'border-indigo-400',
    badgeBg: 'bg-indigo-50',
    badgeText: 'text-indigo-800',
    badgeBorder: 'border-indigo-200',
    cardBg: 'bg-indigo-50/20 hover:bg-indigo-50/50',
    cardBorder: 'border-indigo-200/80',
  },
  EVTX_AUDIT_LOG_CLEARED: {
    label: 'CRITICAL: Audit Log Cleared',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-100',
    bulletBorder: 'border-rose-600',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-900',
    badgeBorder: 'border-rose-400',
    cardBg: 'bg-rose-50/80 hover:bg-rose-50',
    cardBorder: 'border-rose-300',
  },
  EVTX_SYSTEM_TIME_CHANGED: {
    label: 'CRITICAL: System Time Altered',
    icon: (c) => <Clock className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-100',
    bulletBorder: 'border-rose-600',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-900',
    badgeBorder: 'border-rose-400',
    cardBg: 'bg-rose-50/80 hover:bg-rose-50',
    cardBorder: 'border-rose-300',
  },
  PCAP_CAPTURE_START: {
    label: 'PCAP Traffic Ingested',
    icon: (c) => <Network className={c} />,
    iconColor: 'text-cyan-600',
    bulletBg: 'bg-cyan-50',
    bulletBorder: 'border-cyan-400',
    badgeBg: 'bg-cyan-50',
    badgeText: 'text-cyan-800',
    badgeBorder: 'border-cyan-200',
    cardBg: 'bg-cyan-50/20 hover:bg-cyan-50/50',
    cardBorder: 'border-cyan-200/80',
  },
  PCAP_CAPTURE_END: {
    label: 'PCAP Traffic Terminated',
    icon: (c) => <Network className={c} />,
    iconColor: 'text-cyan-600',
    bulletBg: 'bg-cyan-50',
    bulletBorder: 'border-cyan-400',
    badgeBg: 'bg-cyan-50',
    badgeText: 'text-cyan-800',
    badgeBorder: 'border-cyan-200',
    cardBg: 'bg-cyan-50/20 hover:bg-cyan-50/50',
    cardBorder: 'border-cyan-200/80',
  },
  PCAP_DNS_QUERY: {
    label: 'DNS Resolution Query',
    icon: (c) => <Globe className={c} />,
    iconColor: 'text-teal-600',
    bulletBg: 'bg-teal-50',
    bulletBorder: 'border-teal-400',
    badgeBg: 'bg-teal-50',
    badgeText: 'text-teal-800',
    badgeBorder: 'border-teal-200',
    cardBg: 'bg-teal-50/20 hover:bg-teal-50/50',
    cardBorder: 'border-teal-200/80',
  },
  TIMESTOMPING_DELPHI_EPOCH: {
    label: 'Delphi Linker Epoch (Timestomp)',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-100',
    bulletBorder: 'border-rose-600',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-900',
    badgeBorder: 'border-rose-400',
    cardBg: 'bg-rose-50/80 hover:bg-rose-50',
    cardBorder: 'border-rose-300',
  },
  TIMESTOMPING_ZERO_EPOCH: {
    label: 'Zero Epoch Wipe (Timestomp)',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-rose-600',
    bulletBg: 'bg-rose-100',
    bulletBorder: 'border-rose-600',
    badgeBg: 'bg-rose-100',
    badgeText: 'text-rose-900',
    badgeBorder: 'border-rose-400',
    cardBg: 'bg-rose-50/80 hover:bg-rose-50',
    cardBorder: 'border-rose-300',
  },
  TIMESTOMPING_NANOSECOND_ZEROING: {
    label: 'Nanosecond Zeroing Artifact',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-amber-600',
    bulletBg: 'bg-amber-100',
    bulletBorder: 'border-amber-600',
    badgeBg: 'bg-amber-100',
    badgeText: 'text-amber-900',
    badgeBorder: 'border-amber-400',
    cardBg: 'bg-amber-50/80 hover:bg-amber-50',
    cardBorder: 'border-amber-300',
  },
  LNK_FILE_CREATED: {
    label: 'LNK Shortcut Authored',
    icon: (c) => <HardDrive className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-800',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
  LNK_TARGET_MODIFIED: {
    label: 'LNK Target File Modified',
    icon: (c) => <HardDrive className={c} />,
    iconColor: 'text-blue-600',
    bulletBg: 'bg-blue-50',
    bulletBorder: 'border-blue-400',
    badgeBg: 'bg-blue-50',
    badgeText: 'text-blue-800',
    badgeBorder: 'border-blue-200',
    cardBg: 'bg-blue-50/20 hover:bg-blue-50/50',
    cardBorder: 'border-blue-200/80',
  },
};

const DEFAULT_EVENT_TYPE_STYLE: EventTypeStyle = {
  label: 'Timeline Event',
  icon: (c) => <Calendar className={c} />,
  iconColor: 'text-slate-600',
  bulletBg: 'bg-slate-50',
  bulletBorder: 'border-slate-300',
  badgeBg: 'bg-slate-100',
  badgeText: 'text-slate-700',
  badgeBorder: 'border-slate-200',
  cardBg: 'bg-slate-50/60 hover:bg-slate-50',
  cardBorder: 'border-slate-200/80',
};

interface TimelineFilterGroup {
  id: string;
  label: string;
  icon: (className?: string) => React.ReactNode;
  iconColor: string;
  activeBg: string;
  matchEvent: (event: any) => boolean;
}

const ALL_FILTER_GROUPS: TimelineFilterGroup[] = [
  {
    id: 'creation',
    label: 'Creation',
    icon: (c) => <FilePlus className={c} />,
    iconColor: 'text-indigo-600',
    activeBg: 'bg-indigo-600 text-white border-indigo-600 shadow-xs',
    matchEvent: (e) => [
      'FILE_CREATED', 'DOCUMENT_CREATED', 'OFFICE_DOCUMENT_CREATED',
      'PDF_DOCUMENT_CREATED', 'EMBEDDED_FILE_CREATED', 'ARCHIVE_MEMBER_CREATED',
      'CERTIFICATE_ISSUED'
    ].includes(e.event_type),
  },
  {
    id: 'modification',
    label: 'Modification',
    icon: (c) => <FileEdit className={c} />,
    iconColor: 'text-violet-600',
    activeBg: 'bg-violet-600 text-white border-violet-600 shadow-xs',
    matchEvent: (e) => [
      'FILE_MODIFIED', 'DOCUMENT_MODIFIED', 'OFFICE_DOCUMENT_MODIFIED',
      'PDF_DOCUMENT_MODIFIED', 'EMBEDDED_FILE_MODIFIED', 'ARCHIVE_MEMBER_MODIFIED',
      'DOMAIN_UPDATED', 'URL_DOMAIN_UPDATED'
    ].includes(e.event_type),
  },
  {
    id: 'compilation',
    label: 'Compilation',
    icon: (c) => <Cpu className={c} />,
    iconColor: 'text-purple-600',
    activeBg: 'bg-purple-600 text-white border-purple-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'PE_COMPILATION_TIMESTAMP',
  },
  {
    id: 'vt',
    label: 'VirusTotal',
    icon: (c) => <Search className={c} />,
    iconColor: 'text-rose-600',
    activeBg: 'bg-rose-600 text-white border-rose-600 shadow-xs',
    matchEvent: (e) => ['VT_FIRST_SEEN', 'VT_LAST_ANALYSIS'].includes(e.event_type),
  },
  {
    id: 'crowdstrike',
    label: 'CrowdStrike',
    icon: (c) => <Crosshair className={c} />,
    iconColor: 'text-purple-600',
    activeBg: 'bg-purple-600 text-white border-purple-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'CROWDSTRIKE_HYBRID_ANALYSIS',
  },
  {
    id: 'malwarebazaar',
    label: 'MalwareBazaar',
    icon: (c) => <Bug className={c} />,
    iconColor: 'text-red-600',
    activeBg: 'bg-red-600 text-white border-red-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'MALWAREBAZAAR_FIRST_SEEN',
  },
  {
    id: 'threatfox',
    label: 'ThreatFox',
    icon: (c) => <Flame className={c} />,
    iconColor: 'text-orange-600',
    activeBg: 'bg-orange-600 text-white border-orange-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'THREATFOX_FIRST_SEEN',
  },
  {
    id: 'otx',
    label: 'AlienVault OTX',
    icon: (c) => <Radio className={c} />,
    iconColor: 'text-violet-600',
    activeBg: 'bg-violet-600 text-white border-violet-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'OTX_PULSE_REPORTED',
  },
  {
    id: 'anomalies',
    label: 'Timestomping Anomalies',
    icon: (c) => <AlertTriangle className={c} />,
    iconColor: 'text-rose-600',
    activeBg: 'bg-rose-600 text-white border-rose-600 shadow-xs',
    matchEvent: (e) => Boolean(e.is_anomaly) || String(e.event_type).includes('TIMESTOMP') || [
      'EVTX_AUDIT_LOG_CLEARED', 'EVTX_SYSTEM_TIME_CHANGED'
    ].includes(e.event_type),
  },
  {
    id: 'evtx_logs',
    label: 'Windows EVTX Logs',
    icon: (c) => <FileCode className={c} />,
    iconColor: 'text-amber-600',
    activeBg: 'bg-amber-600 text-white border-amber-600 shadow-xs',
    matchEvent: (e) => e.category === 'evtx' || String(e.event_type).startsWith('EVTX_'),
  },
  {
    id: 'pcap_network',
    label: 'PCAP Network Traffic',
    icon: (c) => <Network className={c} />,
    iconColor: 'text-cyan-600',
    activeBg: 'bg-cyan-600 text-white border-cyan-600 shadow-xs',
    matchEvent: (e) => e.category === 'network' || String(e.event_type).startsWith('PCAP_'),
  },
  {
    id: 'previous_submissions',
    label: 'Previous Submissions',
    icon: (c) => <History className={c} />,
    iconColor: 'text-emerald-600',
    activeBg: 'bg-emerald-600 text-white border-emerald-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'PREVIOUS_SUBMISSION',
  },
  {
    id: 'file_ingested',
    label: 'File Ingestion',
    icon: (c) => <UploadCloud className={c} />,
    iconColor: 'text-blue-600',
    activeBg: 'bg-blue-600 text-white border-blue-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'FILE_INGESTED',
  },
  {
    id: 'domains',
    label: 'Domain & WHOIS',
    icon: (c) => <Globe className={c} />,
    iconColor: 'text-sky-600',
    activeBg: 'bg-sky-600 text-white border-sky-600 shadow-xs',
    matchEvent: (e) => [
      'DOMAIN_REGISTERED', 'DOMAIN_UPDATED', 'DOMAIN_EXPIRATION',
      'URL_DOMAIN_REGISTERED', 'URL_DOMAIN_UPDATED',
      'EMAIL_SENDER_DOMAIN_REGISTERED', 'CERTIFICATE_ISSUED', 'CERTIFICATE_EXPIRATION'
    ].includes(e.event_type),
  },
  {
    id: 'email_relay',
    label: 'Email Relay Hops',
    icon: (c) => <Send className={c} />,
    iconColor: 'text-teal-600',
    activeBg: 'bg-teal-600 text-white border-teal-600 shadow-xs',
    matchEvent: (e) => ['EMAIL_ORIGIN_DISPATCH', 'EMAIL_TRANSIT_RELAY'].includes(e.event_type),
  },
  {
    id: 'attachments',
    label: 'Archive & Attachments',
    icon: (c) => <Paperclip className={c} />,
    iconColor: 'text-amber-600',
    activeBg: 'bg-amber-600 text-white border-amber-600 shadow-xs',
    matchEvent: (e) => [
      'ATTACHMENT_TIMESTAMP', 'ATTACHMENT_PAYLOAD_AUTHORED',
      'ARCHIVE_MEMBER_CREATED', 'ARCHIVE_MEMBER_MODIFIED',
      'EMBEDDED_FILE_CREATED', 'EMBEDDED_FILE_MODIFIED'
    ].includes(e.event_type),
  },
  {
    id: 'camera',
    label: 'Photo / EXIF',
    icon: (c) => <Camera className={c} />,
    iconColor: 'text-purple-600',
    activeBg: 'bg-purple-600 text-white border-purple-600 shadow-xs',
    matchEvent: (e) => e.event_type === 'PHOTO_CAPTURED',
  },
];

function formatTimeGap(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  const hours = Math.floor(seconds / 3600);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''}`;
  const days = Math.floor(seconds / 86400);
  if (days < 30) return `${days} day${days > 1 ? 's' : ''}`;
  const months = Math.floor(days / 30.44);
  if (months < 12) {
    const remDays = Math.floor(days % 30.44);
    return remDays > 0 ? `${months} mo ${remDays} d` : `${months} month${months > 1 ? 's' : ''}`;
  }
  const years = Math.floor(days / 365.25);
  const remMonths = Math.floor((days % 365.25) / 30.44);
  return remMonths > 0 ? `${years} yr ${remMonths} mo` : `${years} year${years > 1 ? 's' : ''}`;
}

export const ForensicTimelineCard: React.FC<ForensicTimelineCardProps> = ({ jobId }) => {
  const [timelineData, setTimelineData] = useState<ForensicTimelineData | null>(null);
  const [loading, setLoading] = useState(true);
  const [isSuperTimeline, setIsSuperTimeline] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'canvas' | 'list'>('list');
  const [excludedFiles, setExcludedFiles] = useState<Set<string>>(new Set());

  // Set of active filter group IDs (multiple can be active simultaneously)
  const [activeFilters, setActiveFilters] = useState<Set<string>>(new Set());
  const [groupSimilar, setGroupSimilar] = useState<boolean>(true);
  const [expandedGroupIds, setExpandedGroupIds] = useState<Set<string>>(new Set());

  const fetchTimeline = async (superMode = isSuperTimeline) => {
    setLoading(true);
    try {
      const url = superMode ? `/api/jobs/${jobId}/timeline?mode=super` : `/api/jobs/${jobId}/timeline`;
      const res = await fetch(url);
      if (res.ok) {
        const data: ForensicTimelineData = await res.json();
        setTimelineData(data);
      }
    } catch (err) {
      console.error('Failed to load forensic timeline:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline(isSuperTimeline);
  }, [jobId, isSuperTimeline]);

  // Extract all distinct files and their statistics for Super-Timeline exclusion
  const fileBreakdown = useMemo(() => {
    const map = new Map<string, { count: number; anomalies: number }>();
    (timelineData?.events || []).forEach((e) => {
      const fn = e.filename || 'Primary Artifact';
      const prev = map.get(fn) || { count: 0, anomalies: 0 };
      prev.count += 1;
      if (e.is_anomaly) prev.anomalies += 1;
      map.set(fn, prev);
    });
    return Array.from(map.entries()).map(([filename, stats]) => ({
      filename,
      count: stats.count,
      anomalies: stats.anomalies,
      isExcluded: excludedFiles.has(filename)
    }));
  }, [timelineData?.events, excludedFiles]);

  // Events filtered by excluded files
  const rawEvents = useMemo(() => {
    const all = timelineData?.events || [];
    if (excludedFiles.size === 0) return all;
    return all.filter((e) => {
      const fn = e.filename || 'Primary Artifact';
      return !excludedFiles.has(fn);
    });
  }, [timelineData?.events, excludedFiles]);

  const handleExcludeFile = (filename: string) => {
    setExcludedFiles((prev) => {
      const next = new Set(prev);
      next.add(filename);
      return next;
    });
  };

  const handleIncludeFile = (filename: string) => {
    setExcludedFiles((prev) => {
      const next = new Set(prev);
      next.delete(filename);
      return next;
    });
  };

  const handleRestoreAllFiles = () => {
    setExcludedFiles(new Set());
  };

  const activeSwimlanes = useMemo(() => {
    if (!timelineData?.swimlanes) return undefined;
    if (excludedFiles.size === 0) return timelineData.swimlanes;
    return timelineData.swimlanes.filter((l) => !excludedFiles.has(l.id) && !excludedFiles.has(l.title));
  }, [timelineData?.swimlanes, excludedFiles]);

  const activeCausalityLinks = useMemo(() => {
    if (!timelineData?.causality_links) return undefined;
    if (excludedFiles.size === 0) return timelineData.causality_links;
    const activeIds = new Set(rawEvents.map((e) => e.id));
    return timelineData.causality_links.filter(
      (link) => activeIds.has(link.source_id) && activeIds.has(link.target_id)
    );
  }, [timelineData?.causality_links, rawEvents, excludedFiles]);

  // Compute only filter groups that have at least 1 matching event in this sample's timeline
  const presentFilterGroups = useMemo(() => {
    const groups: Array<TimelineFilterGroup & { count: number }> = [];

    for (const g of ALL_FILTER_GROUPS) {
      const count = rawEvents.filter((e) => g.matchEvent(e)).length;
      if (count > 0) {
        groups.push({ ...g, count });
      }
    }

    // Ensure all events are covered: collect any uncategorized events
    const uncategorized = rawEvents.filter((e) => !ALL_FILTER_GROUPS.some((g) => g.matchEvent(e)));
    if (uncategorized.length > 0) {
      groups.push({
        id: 'other',
        label: 'Other Events',
        icon: (c) => <Calendar className={c} />,
        iconColor: 'text-slate-600',
        activeBg: 'bg-slate-700 text-white border-slate-700 shadow-xs',
        matchEvent: (e) => !ALL_FILTER_GROUPS.some((g) => g.matchEvent(e)),
        count: uncategorized.length,
      });
    }

    return groups;
  }, [rawEvents]);

  // When timeline events change or are first loaded, initialize all present filters as active
  useEffect(() => {
    if (presentFilterGroups.length > 0) {
      setActiveFilters(new Set(presentFilterGroups.map((g) => g.id)));
    }
  }, [presentFilterGroups]);

  // Toggle single filter group
  const handleToggleFilter = (id: string) => {
    setActiveFilters((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Select all present filters
  const handleSelectAllFilters = () => {
    setActiveFilters(new Set(presentFilterGroups.map((g) => g.id)));
  };

  // Deselect all filters
  const handleDeselectAllFilters = () => {
    setActiveFilters(new Set());
  };

  // Filter events: shown if ANY of its matching present groups is active
  const filteredEvents = useMemo(() => {
    if (activeFilters.size === 0) {
      return [];
    }
    return rawEvents
      .filter((e) => {
        const matching = presentFilterGroups.filter((g) => g.matchEvent(e));
        if (matching.length === 0) return true;
        return matching.some((g) => activeFilters.has(g.id));
      })
      .sort((a, b) => a.epoch - b.epoch);
  }, [rawEvents, presentFilterGroups, activeFilters]);

  // Total timeline span in seconds (for relative gap calculations)
  const totalTimelineSpan = useMemo(() => {
    if (filteredEvents.length < 2) return 0;
    const min = filteredEvents[0].epoch;
    const max = filteredEvents[filteredEvents.length - 1].epoch;
    return Math.max(0, max - min);
  }, [filteredEvents]);

  const getEventSimilarityKey = (e: any): string => {
    const normTitle = (e.title || '').trim().toLowerCase();
    const eventType = e.event_type || '';
    const source = e.source || '';
    const category = e.category || '';
    return `${eventType}:::${normTitle}:::${source}:::${category}`;
  };

  // Group consecutive similar activities
  const groupedTimelineItems = useMemo(() => {
    if (!groupSimilar) {
      return filteredEvents.map((event, idx) => ({
        id: `single-${event.id || idx}`,
        isGroup: false,
        events: [event],
        firstEvent: event,
        lastEvent: event,
        count: 1,
        cfg: EVENT_TYPE_CONFIG[event.event_type] || DEFAULT_EVENT_TYPE_STYLE,
      }));
    }

    const items: Array<{
      id: string;
      isGroup: boolean;
      events: any[];
      firstEvent: any;
      lastEvent: any;
      count: number;
      cfg: any;
    }> = [];

    for (let i = 0; i < filteredEvents.length; i++) {
      const current = filteredEvents[i];
      const currentKey = getEventSimilarityKey(current);

      if (items.length > 0) {
        const lastItem = items[items.length - 1];
        const lastKey = getEventSimilarityKey(lastItem.events[0]);

        // Consecutive similar events with same signature and same anomaly status
        if (currentKey === lastKey && Boolean(current.is_anomaly) === Boolean(lastItem.events[0].is_anomaly)) {
          lastItem.events.push(current);
          lastItem.lastEvent = current;
          lastItem.count = lastItem.events.length;
          lastItem.isGroup = true;
          continue;
        }
      }

      items.push({
        id: `group-${current.id || i}-${current.epoch}`,
        isGroup: false,
        events: [current],
        firstEvent: current,
        lastEvent: current,
        count: 1,
        cfg: EVENT_TYPE_CONFIG[current.event_type] || DEFAULT_EVENT_TYPE_STYLE,
      });
    }

    return items;
  }, [filteredEvents, groupSimilar]);

  if (loading) {
    return (
      <div className="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm text-center">
        <RefreshCw className="w-8 h-8 text-indigo-500 animate-spin mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-800">Reconstructing Forensic Event Timeline...</h3>
        <p className="text-xs text-slate-500 font-mono mt-1">
          Correlating filesystem timestamps, metadata MACB times, and email transit hops.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header and Action Controls */}
      <div className="bg-white rounded-3xl border border-slate-200 p-6 sm:p-8 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="p-1.5 bg-indigo-50 text-indigo-600 rounded-lg">
                <Clock className="w-5 h-5" />
              </span>
              <h3 className="text-lg font-bold text-slate-900">
                Forensic Timeline &amp; Incident Event Reconstruction
              </h3>
            </div>
            <p className="text-xs text-slate-500 font-mono">
              Chronologically sorted event log across filesystem, document revisions, online threat intel, and anti-forensic timestomping indicators.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* View Mode Toggle: [Kill-Chain Swimlanes] / [Event List] */}
            <div className="flex items-center bg-slate-100 p-0.5 rounded-xl border border-slate-200">
              <button
                type="button"
                onClick={() => setViewMode('canvas')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  viewMode === 'canvas'
                    ? 'bg-white text-indigo-700 shadow-xs font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Activity className="w-3.5 h-3.5 text-indigo-600" />
                <span>Kill-Chain Swimlanes</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('list')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  viewMode === 'list'
                    ? 'bg-white text-slate-900 shadow-xs font-bold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <SlidersHorizontal className="w-3.5 h-3.5 text-slate-600" />
                <span>Event List ({rawEvents.length})</span>
              </button>
            </div>

            {/* Super-Timeline Toggle Button */}
            <button
              type="button"
              onClick={() => setIsSuperTimeline(!isSuperTimeline)}
              className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-xl border transition-colors cursor-pointer ${
                isSuperTimeline
                  ? 'bg-purple-600 text-white border-purple-600 shadow-xs'
                  : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200 shadow-2xs'
              }`}
              title="Toggle master Super-Timeline correlating all chronological events across workspace artifacts"
            >
              <Sparkles className={`w-3.5 h-3.5 ${isSuperTimeline ? 'text-white' : 'text-purple-600'}`} />
              <span>{isSuperTimeline ? 'Unified Super-Timeline (Active)' : 'Super-Timeline Mode'}</span>
            </button>
            <a
              href={`/api/jobs/${jobId}/timeline/export?format=csv`}
              download
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl border border-slate-200 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV (Plaso)</span>
            </a>
            <a
              href={`/api/jobs/${jobId}/timeline/export?format=json`}
              download
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold rounded-xl border border-indigo-200 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </a>
          </div>
        </div>

        {/* Unified Super-Timeline File Exclusion Toolbar */}
        {(isSuperTimeline || fileBreakdown.length > 1) && (
          <div className="mt-5 p-4 bg-purple-50/60 border border-purple-200/80 rounded-2xl">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5">
              <div className="flex items-center gap-2">
                <span className="p-1.5 bg-purple-100 text-purple-700 rounded-lg">
                  <Layers className="w-4 h-4" />
                </span>
                <div>
                  <h4 className="text-xs font-bold text-purple-950 uppercase tracking-wider flex items-center gap-2">
                    <span>Super-Timeline Included Files</span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-purple-200/80 text-purple-900 font-bold">
                      {fileBreakdown.length - excludedFiles.size} of {fileBreakdown.length} Active
                    </span>
                  </h4>
                  <p className="text-[11px] text-purple-800">
                    Click the <strong>×</strong> on any file to exclude it from the timeline analysis, swimlanes, and anomaly detection.
                  </p>
                </div>
              </div>

              {excludedFiles.size > 0 && (
                <button
                  type="button"
                  onClick={handleRestoreAllFiles}
                  className="px-2.5 py-1 text-xs font-semibold rounded-lg bg-white border border-purple-300 text-purple-800 hover:bg-purple-100/60 transition-colors flex items-center gap-1.5 shadow-2xs cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5 text-purple-700" />
                  <span>Restore All Files ({excludedFiles.size} excluded)</span>
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2 pt-1">
              {fileBreakdown.map((item) => {
                const isExcluded = item.isExcluded;
                return (
                  <div
                    key={item.filename}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-mono transition-all ${
                      isExcluded
                        ? 'bg-slate-100 border-slate-200 text-slate-400 line-through opacity-70'
                        : 'bg-white border-purple-200 text-purple-950 shadow-2xs'
                    }`}
                  >
                    <FileText className={`w-3.5 h-3.5 ${isExcluded ? 'text-slate-400' : 'text-purple-600'}`} />
                    <span className="font-semibold">{item.filename}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] ${
                      isExcluded ? 'bg-slate-200 text-slate-500' : 'bg-purple-100 text-purple-800 font-bold'
                    }`}>
                      {item.count} evt{item.count !== 1 ? 's' : ''}
                    </span>
                    {item.anomalies > 0 && !isExcluded && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-100 text-rose-700 font-bold border border-rose-200">
                        {item.anomalies} anom
                      </span>
                    )}

                    {isExcluded ? (
                      <button
                        type="button"
                        onClick={() => handleIncludeFile(item.filename)}
                        className="ml-1 p-0.5 rounded text-purple-700 hover:bg-purple-100 cursor-pointer no-underline"
                        title="Re-include this file in timeline"
                      >
                        <RotateCcw className="w-3 h-3" />
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleExcludeFile(item.filename)}
                        className="ml-1 p-0.5 rounded text-slate-400 hover:text-rose-600 hover:bg-rose-50 cursor-pointer"
                        title="Remove this file from timeline analysis"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Timestomping & Temporal Anomaly Alert Drawer */}
        {((timelineData?.anomalies_count && timelineData.anomalies_count > 0) || rawEvents.some((e) => e.is_anomaly)) && (
          <div className="mt-5 p-4 bg-rose-50 border border-rose-200 rounded-2xl">
            <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
                <h4 className="text-xs font-bold text-rose-900 uppercase tracking-wider">
                  Anti-Forensic Timestomping &amp; Temporal Paradoxes Detected ({rawEvents.filter((e) => e.is_anomaly).length})
                </h4>
              </div>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded bg-rose-600 text-white shadow-2xs">
                MITRE T1070.006 (Indicator Removal: Timestomp)
              </span>
            </div>
            <p className="text-xs text-rose-800 mb-3">
              Chronological discrepancies identified across artifact metadata. The timestamps exhibit deliberate modifications, synthetic linker default epochs, future dating, or audit log clearing.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
              {rawEvents
                .filter((e) => e.is_anomaly)
                .slice(0, 6)
                .map((anom, idx) => (
                  <div key={idx} className="p-3 bg-white border border-rose-200 rounded-xl flex items-start gap-2.5 shadow-2xs">
                    <div className="w-2 h-2 rounded-full bg-rose-600 shrink-0 mt-1.5" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="font-semibold text-rose-950 font-mono text-[11px] truncate">
                          {anom.title}
                        </span>
                        <span className="px-1.5 py-0.2 text-[9px] uppercase font-bold rounded bg-rose-100 text-rose-800 border border-rose-200 shrink-0">
                          {anom.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600 line-clamp-2 leading-relaxed">
                        {anom.description}
                      </p>
                      <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-slate-100 text-[10px] font-mono text-slate-400">
                        <span>Source: {anom.source}</span>
                        <span>{anom.timestamp}</span>
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* View Mode Branch */}
        {viewMode === 'canvas' ? (
          <div className="pt-6">
            <MultiArtifactSwimlaneCanvas
              events={rawEvents}
              swimlanes={activeSwimlanes}
              causalityLinks={activeCausalityLinks}
              jobId={jobId}
              isSuperTimeline={isSuperTimeline}
              onRemoveLane={handleExcludeFile}
            />
          </div>
        ) : (
          <div>
            {/* Dynamic Multi-Select Filter Bar */}
            <div className="pt-5 pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
                <SlidersHorizontal className="w-3.5 h-3.5 text-indigo-600" />
                <span>Timeline Event Filters</span>
              </span>
              <span className="text-xs font-mono font-medium text-slate-500">
                ({activeFilters.size}/{presentFilterGroups.length} active • Showing {filteredEvents.length} of {rawEvents.length} events)
              </span>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              {/* Group Similar Activities Filter Toggle */}
              <label
                id="timeline-group-similar-label"
                className={`px-2.5 py-1 text-[11px] font-semibold border rounded-lg transition-all cursor-pointer select-none flex items-center gap-1.5 shadow-2xs ${
                  groupSimilar
                    ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
                    : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300'
                }`}
                title="Group consecutive similar activities together"
              >
                <input
                  type="checkbox"
                  id="timeline-group-similar"
                  checked={groupSimilar}
                  onChange={(e) => setGroupSimilar(e.target.checked)}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer w-3.5 h-3.5"
                />
                <Layers className="w-3.5 h-3.5 text-indigo-600" />
                <span>Group similar activities</span>
                {groupSimilar && filteredEvents.length - groupedTimelineItems.length > 0 && (
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold bg-indigo-200/80 text-indigo-900">
                    -{filteredEvents.length - groupedTimelineItems.length}
                  </span>
                )}
              </label>

              <button
                type="button"
                onClick={handleSelectAllFilters}
                className="px-2.5 py-1 text-[11px] font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors cursor-pointer flex items-center gap-1 border border-slate-200"
                title="Enable all available event filters"
              >
                <CheckSquare className="w-3 h-3 text-indigo-600" />
                <span>Select All</span>
              </button>
              <button
                type="button"
                onClick={handleDeselectAllFilters}
                className="px-2.5 py-1 text-[11px] font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors cursor-pointer flex items-center gap-1 border border-slate-200"
                title="Deselect all event filters"
              >
                <Square className="w-3 h-3 text-slate-400" />
                <span>Clear All</span>
              </button>
            </div>
          </div>

          {/* Interactive Multi-Select Filter Chips Grid */}
          <div className="flex flex-wrap items-center gap-2">
            {presentFilterGroups.map((group) => {
              const isActive = activeFilters.has(group.id);
              return (
                <button
                  key={group.id}
                  type="button"
                  onClick={() => handleToggleFilter(group.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all cursor-pointer select-none ${
                    isActive
                      ? `${group.activeBg}`
                      : 'bg-white text-slate-400 border-slate-200 hover:border-slate-300 hover:text-slate-600 opacity-60 hover:opacity-100'
                  }`}
                >
                  <span className={isActive ? 'text-white' : group.iconColor}>
                    {group.icon('w-3.5 h-3.5')}
                  </span>
                  <span>{group.label}</span>
                  <span
                    className={`font-mono text-[10px] font-bold px-1.5 py-0.2 rounded ${
                      isActive
                        ? 'bg-black/20 text-white'
                        : 'bg-slate-100 text-slate-500 border border-slate-200'
                    }`}
                  >
                    {group.count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Timeline Event List with Zigzag Time Gap Visualizer */}
        {filteredEvents.length === 0 ? (
          <div className="mt-8 p-8 bg-slate-50 border border-slate-200 rounded-2xl text-center">
            <CheckCircle2 className="w-8 h-8 text-slate-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-700">No events match the selected filters.</p>
            <p className="text-xs text-slate-400 mt-1">
              Select one or more filter chips above, or click "Select All" to view all events.
            </p>
          </div>
        ) : (
          <div className="mt-8 relative border-l-2 border-slate-200 ml-4 sm:ml-6 space-y-6">
            {groupedTimelineItems.map((item, idx) => {
              const event = item.firstEvent;
              const cfg = item.cfg;
              const isGroup = item.isGroup && item.count > 1;
              const isExpanded = expandedGroupIds.has(item.id);

              // Check if there is a long time gap between this item and the next item
              let isLongGap = false;
              let gapSeconds = 0;
              let gapRatio = 0;

              if (idx < groupedTimelineItems.length - 1) {
                const nextItem = groupedTimelineItems[idx + 1];
                gapSeconds = Math.max(0, nextItem.firstEvent.epoch - item.lastEvent.epoch);
                if (totalTimelineSpan > 0) {
                  gapRatio = gapSeconds / totalTimelineSpan;
                }
                // Long gap condition:
                // 1) Gap accounts for >= 15% of the total timeline AND is >= 24 hours, OR
                // 2) Absolute gap is >= 14 days (2 weeks)
                if (gapSeconds >= 86400 * 14 || (totalTimelineSpan >= 86400 * 2 && gapRatio >= 0.15 && gapSeconds >= 86400)) {
                  isLongGap = true;
                }
              }

              return (
                <React.Fragment key={item.id || idx}>
                  <div className="relative pl-6 sm:pl-8 group">
                    {/* Node Bullet with Event Type Custom Icon & Subtle Color Hint */}
                    <div
                      className={`absolute -left-[17px] top-1.5 w-8 h-8 rounded-full border-2 flex items-center justify-center shadow-xs transition-transform group-hover:scale-110 z-5 ${
                        event.is_anomaly
                          ? 'border-rose-500 bg-rose-50'
                          : event.severity === 'critical'
                          ? 'border-rose-400 bg-rose-50/50'
                          : event.severity === 'warning'
                          ? 'border-amber-400 bg-amber-50/50'
                          : `${cfg.bulletBorder} ${cfg.bulletBg}`
                      }`}
                      title={`${cfg.label} (${event.source})`}
                    >
                      {event.is_anomaly ? (
                        <AlertTriangle className="w-4 h-4 text-rose-600" />
                      ) : (
                        cfg.icon(`w-4 h-4 ${cfg.iconColor}`)
                      )}
                    </div>

                    {/* Event Card with Subtle Color Tint */}
                    <div
                      className={`p-4 rounded-2xl border transition-all ${
                        event.is_anomaly
                          ? 'bg-rose-50/80 border-rose-300 shadow-sm'
                          : `${cfg.cardBg} ${cfg.cardBorder}`
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-slate-800">
                            {isGroup ? (
                              <span>
                                {item.firstEvent.timestamp.replace('T', ' ').replace('Z', ' UTC')}
                                <span className="text-slate-400 font-normal mx-1">↳</span>
                                {item.lastEvent.timestamp.replace('T', ' ').replace('Z', ' UTC')}
                              </span>
                            ) : (
                              event.timestamp.replace('T', ' ').replace('Z', ' UTC')
                            )}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider font-semibold border ${
                              event.is_anomaly
                                ? 'bg-rose-100 text-rose-800 border-rose-200'
                                : `${cfg.badgeBg} ${cfg.badgeText} ${cfg.badgeBorder}`
                            }`}
                          >
                            {event.source}
                          </span>
                          {/* Event Type Name Badge */}
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-white/80 text-slate-600 border border-slate-200/90 shadow-2xs">
                            {cfg.label}
                          </span>
                          {isGroup && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-indigo-100 text-indigo-800 border border-indigo-200 flex items-center gap-1 shadow-2xs">
                              <Layers className="w-3 h-3 text-indigo-600" />
                              <span>{item.count}x Grouped Activities</span>
                            </span>
                          )}
                          {event.category === 'history' && (
                            <span className="px-2 py-0.5 bg-emerald-100 text-emerald-800 border border-emerald-300 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1">
                              <span>🕒</span> Previous Submission
                            </span>
                          )}
                        </div>
                        {event.is_anomaly && (
                          <span className="px-2 py-0.5 bg-rose-600 text-white rounded text-[10px] font-bold uppercase tracking-wider">
                            ⚠️ Timestomping Anomaly
                          </span>
                        )}
                      </div>

                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1">
                          <h4
                            className={`text-sm font-bold ${
                              event.is_anomaly ? 'text-rose-950' : 'text-slate-900'
                            }`}
                          >
                            {event.title}
                          </h4>
                          {event.description && (
                            <p
                              className={`text-xs mt-1 leading-relaxed ${
                                event.is_anomaly ? 'text-rose-900/90' : 'text-slate-600'
                              }`}
                            >
                              {event.description}
                            </p>
                          )}
                        </div>

                        {isGroup && (
                          <button
                            type="button"
                            onClick={() => {
                              setExpandedGroupIds((prev) => {
                                const next = new Set(prev);
                                if (next.has(item.id)) next.delete(item.id);
                                else next.add(item.id);
                                return next;
                              });
                            }}
                            className="shrink-0 px-2.5 py-1 rounded-xl bg-white hover:bg-slate-100 border border-slate-200 text-indigo-700 text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer shadow-2xs select-none"
                          >
                            <span>{isExpanded ? 'Collapse' : `View all ${item.count}`}</span>
                            {isExpanded ? (
                              <ChevronDown className="w-3.5 h-3.5 rotate-180 transition-transform" />
                            ) : (
                              <ChevronDown className="w-3.5 h-3.5 transition-transform" />
                            )}
                          </button>
                        )}
                      </div>

                      {/* Sub-events expanded list */}
                      {isGroup && isExpanded && (
                        <div className="mt-3 pt-3 border-t border-slate-200/80 space-y-2">
                          <div className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                            Consecutive Occurrences ({item.count}):
                          </div>
                          <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                            {item.events.map((subEv, subIdx) => (
                              <div key={subIdx} className="p-2 bg-white/90 border border-slate-200 rounded-xl text-xs flex items-start justify-between gap-2 shadow-2xs">
                                <div className="space-y-0.5">
                                  <span className="font-mono text-[11px] font-bold text-slate-700">
                                    #{subIdx + 1} • {subEv.timestamp.replace('T', ' ').replace('Z', ' UTC')}
                                  </span>
                                  {subEv.description && subEv.description !== event.description && (
                                    <p className="text-[11px] text-slate-500 leading-snug">{subEv.description}</p>
                                  )}
                                </div>
                                <span className="font-mono text-[10px] text-slate-400 shrink-0">
                                  {subEv.source}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Relative Disconnected Time Gap: Zigzag Vertical Line & Break Indicator */}
                  {isLongGap && (
                    <div className="relative py-2 my-1 flex items-center">
                      {/* Opaque container masking the straight vertical border with the Zigzag line in the EXACT same slate color */}
                      <div className="absolute -left-[10px] w-5 bg-white z-10 flex flex-col items-center justify-center">
                        <svg width="18" height="52" viewBox="0 0 18 52" fill="none" className="text-slate-300">
                          <path
                            d="M 9,0 L 9,6 L 2,13 L 16,21 L 2,29 L 16,37 L 9,44 L 9,52"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        </svg>
                      </div>

                      {/* Time gap indicator badge */}
                      <div className="ml-7 sm:ml-9 inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-50 border border-slate-300/80 text-slate-800 text-xs font-mono shadow-2xs">
                        <span className="font-bold flex items-center gap-1 text-slate-700">
                          <span>⚡</span> Disconnected Temporal Era:
                        </span>
                        <span className="font-semibold text-slate-900 bg-slate-200/70 px-1.5 py-0.5 rounded">
                          +{formatTimeGap(gapSeconds)}
                        </span>
                        <span className="text-[11px] text-slate-500 font-sans hidden sm:inline">
                          ({Math.round(gapRatio * 100)}% of total timeline duration)
                        </span>
                      </div>
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        )}
      </div>
    )}
  </div>
</div>
  );
};
