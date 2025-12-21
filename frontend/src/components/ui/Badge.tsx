import React from 'react';
import { BadgeSeverityType, BadgeStatusType, BadgeType } from '../../types';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'status' | 'severity' | 'primary' | 'success' | 'warning' | 'danger';
  type?: BadgeType;
  className?: string;
}

// Re-export types for convenience
export type { BadgeSeverityType, BadgeStatusType, BadgeType };

const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'status',
  type = 'pending',
  className = '',
}) => {
  const baseStyles = 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium';

  const statusStyles = {
    pending: 'bg-status-pending/20 text-status-pending border border-status-pending/30',
    running: 'bg-status-running/20 text-status-running border border-status-running/30',
    completed: 'bg-status-completed/20 text-status-completed border border-status-completed/30',
    failed: 'bg-status-failed/20 text-status-failed border border-status-failed/30',
  };

  const severityStyles = {
    critical: 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30',
    high: 'bg-severity-high/20 text-severity-high border border-severity-high/30',
    medium: 'bg-severity-medium/20 text-severity-medium border border-severity-medium/30',
    low: 'bg-severity-low/20 text-severity-low border border-severity-low/30',
  };

  // Direct color variants for simpler usage
  const colorVariants: Record<string, string> = {
    primary: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    success: 'bg-green-500/20 text-green-400 border border-green-500/30',
    warning: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    danger: 'bg-red-500/20 text-red-400 border border-red-500/30',
  };

  // Check if variant is a direct color variant
  if (variant && colorVariants[variant]) {
    return (
      <span className={`${baseStyles} ${colorVariants[variant]} ${className}`}>
        {children}
      </span>
    );
  }

  const styles = variant === 'status' ? statusStyles : severityStyles;
  const typeStyles = styles[type as keyof typeof styles] || statusStyles.pending;

  return (
    <span className={`${baseStyles} ${typeStyles} ${className}`}>
      {children}
    </span>
  );
};

export { Badge };
export default Badge;
