// ============================================================================
// Common Types - Basic types and utilities used across the application
// ============================================================================

export type UserRole = 'admin' | 'user' | 'auditor' | 'viewer';

// Badge type definitions for type-safe severity/status rendering
export type BadgeSeverityType = 'critical' | 'high' | 'medium' | 'low';
export type BadgeStatusType = 'pending' | 'running' | 'completed' | 'failed';
export type BadgeType = BadgeSeverityType | BadgeStatusType;

/**
 * Convert a severity string to a type-safe badge type.
 * Handles both uppercase (from API) and lowercase formats.
 */
export function toSeverityBadgeType(severity: string): BadgeSeverityType {
  const normalized = severity.toLowerCase();
  switch (normalized) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
    case 'info':
    case 'informational':
      return 'low';
    default:
      return 'low';
  }
}
