// ============================================================================
// Common Types - Basic types and utilities used across the application
// ============================================================================

// Base user roles
export type UserRole =
  | 'admin'
  | 'user'
  | 'auditor'
  | 'viewer'
  // Team-based roles for colored team views
  | 'red_team'
  | 'blue_team'
  | 'yellow_team'
  | 'white_team'
  | 'orange_team'
  | 'green_team'
  | 'purple_team';

// Team role type for type-safe team operations
export type TeamRole =
  | 'red_team'
  | 'blue_team'
  | 'yellow_team'
  | 'white_team'
  | 'orange_team'
  | 'green_team'
  | 'purple_team';

// Array of all team roles for iteration
export const TEAM_ROLES: TeamRole[] = [
  'red_team',
  'blue_team',
  'yellow_team',
  'white_team',
  'orange_team',
  'green_team',
  'purple_team',
];

// Team color mapping for UI theming
export const TEAM_COLORS: Record<TeamRole, string> = {
  red_team: '#ef4444',
  blue_team: '#3b82f6',
  yellow_team: '#eab308',
  white_team: '#94a3b8',
  orange_team: '#f97316',
  green_team: '#22c55e',
  purple_team: '#a855f7',
};

// Team display names
export const TEAM_LABELS: Record<TeamRole, string> = {
  red_team: 'Red Team',
  blue_team: 'Blue Team',
  yellow_team: 'Yellow Team',
  white_team: 'White Team',
  orange_team: 'Orange Team',
  green_team: 'Green Team',
  purple_team: 'Purple Team',
};

// Helper to check if a role is a team role
export function isTeamRole(role: string): role is TeamRole {
  return TEAM_ROLES.includes(role as TeamRole);
}

// Get team color for accent theming
export function getTeamColor(role: TeamRole): string {
  return TEAM_COLORS[role];
}

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
