// ============================================================================
// Admin Console Types - Roles, Audit Logs, System Settings, API Keys
// ============================================================================

import type { UserRole } from './common';

export interface Role {
  id: string;
  name: string;
  description?: string;
  can_manage_users: boolean;
  can_manage_scans: boolean;
  can_view_all_scans: boolean;
  can_delete_any_scan: boolean;
  can_view_audit_logs: boolean;
  can_manage_settings: boolean;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  username?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  details?: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

export interface AuditLogResponse {
  logs: AuditLog[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditLogFilter {
  user_id?: string;
  action?: string;
  target_type?: string;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
}

export interface AuditUser {
  id: string;
  username: string;
  email: string;
}

export interface SystemSetting {
  key: string;
  value: string;
  description?: string;
  updated_by?: string;
  updated_at: string;
}

// API Keys types
export interface ApiKey {
  id: string;
  user_id: string;
  name: string;
  prefix: string;
  permissions: string[] | null;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  is_active: boolean;
}

export interface CreateApiKeyRequest {
  name: string;
  permissions?: string[];
  expires_at?: string;
}

export interface CreateApiKeyResponse {
  id: string;
  name: string;
  key: string; // Full key (only returned once)
  prefix: string;
  permissions: string[] | null;
  created_at: string;
  expires_at: string | null;
}

export interface UpdateApiKeyRequest {
  name?: string;
  permissions?: string[];
}

// Rate Limit Dashboard Types

export type RateLimitCategory = 'auth' | 'api' | 'scan';

export interface RateLimitConfig {
  category: RateLimitCategory;
  name: string;
  requests_per_period: number;
  period: string;
  burst_size: number;
  description: string;
}

export interface RateLimitEvent {
  id: string;
  ip: string;
  category: RateLimitCategory;
  endpoint: string;
  timestamp: string;
  user_agent: string | null;
}

export interface IpStats {
  ip: string;
  total_requests: number;
  blocked_requests: number;
  last_seen: string;
  requests_by_category: Record<string, number>;
}

export interface RateLimitSummary {
  total_requests_24h: number;
  blocked_requests_24h: number;
  block_rate_percent: number;
  unique_ips_24h: number;
  requests_by_category: Record<string, number>;
  blocked_by_category: Record<string, number>;
}

export interface RequestTimePoint {
  timestamp: string;
  total_requests: number;
  blocked_requests: number;
}

export interface RateLimitDashboardData {
  configs: RateLimitConfig[];
  summary: RateLimitSummary;
  recent_events: RateLimitEvent[];
  top_ips: IpStats[];
  requests_over_time: RequestTimePoint[];
}

// Extended role assignment info with organization details (from admin API)
export interface RoleAssignmentInfo {
  id: string;
  role_type: 'template' | 'custom' | 'Template' | 'Custom';
  role_id: string;
  role_name: string;
  role_display_name: string;
  organization_id?: string;
  organization_name?: string;
  scope_type?: string;
  scope_id?: string;
  scope_name?: string;
  assigned_at: string;
  assigned_by?: string;
  expires_at?: string;
  is_active: boolean;
}

// Permission summary for admin user list
export interface PermissionsSummary {
  role_count: number;
  organization_count: number;
  has_admin_role: boolean;
}

// Extended user type for admin API response
export interface AdminUser {
  id: string;
  username: string;
  email: string;
  is_active: boolean;
  created_at: string;
  mfa_enabled: boolean;
  roles: UserRole[];  // Legacy roles for backward compatibility
  role_assignments: RoleAssignmentInfo[];  // ABAC role assignments
  permissions_summary: PermissionsSummary;
  is_locked: boolean;
  locked_until?: string;
  failed_attempts: number;
}
