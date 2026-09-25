import { RiskLevel } from '../types';

export function formatBytes(bytes: number, decimals: number = 2): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function truncateHash(hash: string, start: number = 8, end: number = 8): string {
  if (!hash || hash.length <= start + end) return hash || '';
  return `${hash.slice(0, start)}...${hash.slice(-end)}`;
}

export function getRiskColors(level: RiskLevel | string): {
  bg: string;
  text: string;
  border: string;
  badgeBg: string;
  badgeText: string;
} {
  switch (level) {
    case 'MALICIOUS':
      return {
        bg: 'bg-rose-50',
        text: 'text-rose-900',
        border: 'border-rose-300',
        badgeBg: 'bg-rose-600',
        badgeText: 'text-white'
      };
    case 'HIGH RISK':
      return {
        bg: 'bg-red-50',
        text: 'text-red-900',
        border: 'border-red-300',
        badgeBg: 'bg-red-500',
        badgeText: 'text-white'
      };
    case 'MEDIUM RISK':
      return {
        bg: 'bg-amber-50',
        text: 'text-amber-900',
        border: 'border-amber-300',
        badgeBg: 'bg-amber-500',
        badgeText: 'text-white'
      };
    case 'LOW RISK':
      return {
        bg: 'bg-slate-50',
        text: 'text-slate-800',
        border: 'border-slate-300',
        badgeBg: 'bg-slate-600',
        badgeText: 'text-white'
      };
    case 'CLEAN':
    default:
      return {
        bg: 'bg-emerald-50',
        text: 'text-emerald-900',
        border: 'border-emerald-300',
        badgeBg: 'bg-emerald-600',
        badgeText: 'text-white'
      };
  }
}
