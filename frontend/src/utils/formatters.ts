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

export interface TimeDisplayConfig {
  format: '24h' | '12h';
  time_zone: string; // 'UTC', 'local', or IANA tz e.g. 'America/New_York', 'Europe/Stockholm'
  show_timezone_suffix?: boolean;
  show_milliseconds?: boolean;
}

export function getTimeDisplayConfig(): TimeDisplayConfig {
  try {
    const saved = localStorage.getItem('fs_time_display');
    if (saved) {
      return JSON.parse(saved);
    }
  } catch {}
  return {
    format: '24h',
    time_zone: 'UTC',
    show_timezone_suffix: true,
    show_milliseconds: false,
  };
}

export function setTimeDisplayConfig(config: TimeDisplayConfig): void {
  try {
    localStorage.setItem('fs_time_display', JSON.stringify(config));
    window.dispatchEvent(new Event('fs_time_display_changed'));
  } catch {}
}

/**
 * Format any ISO 8601 or date string into user-customized 24h/12h and target timezone format.
 */
export function formatTimestamp(isoStr?: string | null, customConfig?: Partial<TimeDisplayConfig>): string {
  if (!isoStr) return 'N/A';
  try {
    const date = new Date(isoStr);
    if (isNaN(date.getTime())) return isoStr;

    const baseConfig = getTimeDisplayConfig();
    const config: TimeDisplayConfig = { ...baseConfig, ...customConfig };

    const isUtc = config.time_zone === 'UTC';
    const isLocal = config.time_zone === 'local';
    const targetTz = isUtc ? 'UTC' : isLocal ? undefined : config.time_zone;

    const options: Intl.DateTimeFormatOptions = {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: config.format === '12h',
    };

    if (targetTz) {
      options.timeZone = targetTz;
    }

    let datePart = '';

    if (config.format === '24h') {
      // Use sv-SE for standard ISO-like YYYY-MM-DD HH:mm:ss
      const svFormatter = new Intl.DateTimeFormat('sv-SE', options);
      const formatted = svFormatter.format(date);
      datePart = formatted;
    } else {
      const enFormatter = new Intl.DateTimeFormat('en-US', options);
      datePart = enFormatter.format(date);
    }

    let result = datePart;

    if (config.show_milliseconds) {
      const ms = String(date.getMilliseconds()).padStart(3, '0');
      // insert ms before AM/PM if 12h, or append
      if (result.includes(' AM') || result.includes(' PM')) {
        result = result.replace(/ (AM|PM)/, `.${ms} $1`);
      } else {
        result += `.${ms}`;
      }
    }

    if (config.show_timezone_suffix) {
      let tzLabel = 'UTC';
      if (isLocal) {
        tzLabel = Intl.DateTimeFormat().resolvedOptions().timeZone.split('/').pop()?.replace(/_/g, ' ') || 'Local';
      } else if (!isUtc) {
        tzLabel = config.time_zone.split('/').pop()?.replace(/_/g, ' ') || config.time_zone;
      }
      result += ` [${tzLabel}]`;
    }

    return result;
  } catch {
    return isoStr;
  }
}
