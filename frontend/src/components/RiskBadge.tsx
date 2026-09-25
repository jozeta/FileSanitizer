import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, ShieldX } from 'lucide-react';
import { RiskLevel } from '../types';
import { getRiskColors } from '../utils/formatters';

interface RiskBadgeProps {
  level: RiskLevel | string;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = 'md' }) => {
  const colors = getRiskColors(level);

  const getIcon = () => {
    switch (level) {
      case 'MALICIOUS':
        return <ShieldX className={size === 'lg' ? 'w-6 h-6' : size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
      case 'HIGH RISK':
        return <AlertTriangle className={size === 'lg' ? 'w-6 h-6' : size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
      case 'MEDIUM RISK':
        return <AlertTriangle className={size === 'lg' ? 'w-6 h-6' : size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
      case 'LOW RISK':
        return <ShieldAlert className={size === 'lg' ? 'w-6 h-6' : size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
      case 'CLEAN':
      default:
        return <ShieldCheck className={size === 'lg' ? 'w-6 h-6' : size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
    }
  };

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs gap-1',
    md: 'px-3 py-1 text-xs gap-1.5 font-semibold',
    lg: 'px-4 py-2 text-sm gap-2 font-bold'
  };

  return (
    <span className={`inline-flex items-center rounded-full uppercase tracking-wider ${sizeClasses[size]} ${colors.badgeBg} ${colors.badgeText} shadow-sm`}>
      {getIcon()}
      <span>{level}</span>
    </span>
  );
};
